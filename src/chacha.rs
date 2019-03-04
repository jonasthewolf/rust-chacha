// Type of inner state of chacha
const INNER_STATE_SIZE: usize = 16;
type InnerState = [u32; INNER_STATE_SIZE];

const NONCE_LENGTH: usize = 3;
// Type of nonce
pub type Nonce = [u32; NONCE_LENGTH];

// Index of block number
const BLOCK_NUMBER_INDEX: usize = 12;

// Structure for chacha algorithm
pub struct Chacha {
	// The state
	state: InnerState,
}

impl Chacha {
	pub fn new(k: &[u8], n: &Nonce) -> Chacha {
		assert!(k.len() == 32);
		Chacha {
			state: [
				0x61707865u32.to_le(),
				0x3320646eu32.to_le(),
				0x79622d32u32.to_le(),
				0x6b206574u32.to_le(),
				u32::from_le_bytes([k[0],  k[1],  k[2],  k[3]]),
				u32::from_le_bytes([k[4],  k[5],  k[6],  k[7]]),
				u32::from_le_bytes([k[8],  k[9],  k[10], k[11]]),
				u32::from_le_bytes([k[12], k[13], k[14], k[15]]),
				u32::from_le_bytes([k[16], k[17], k[18], k[19]]),
				u32::from_le_bytes([k[20], k[21], k[22], k[23]]),
				u32::from_le_bytes([k[24], k[25], k[26], k[27]]),
				u32::from_le_bytes([k[28], k[29], k[30], k[31]]),
				0, /* BN */
				n[0].to_le(),
				n[1].to_le(),
				n[2].to_le(),
			],
		}
	}

	/// Generates a block of key stream for the given block number
	//
	// Params:
	//   keystream = at least 64 bytes of memory for the generated key stream
	//   blocknumber = the blocknumber to generate the keystream for
	//
	pub fn get_keystream(&mut self, keystream: &mut [u8], blocknumber: u32) {
		assert!(keystream.len() == INNER_STATE_SIZE * 4);
		self.state[BLOCK_NUMBER_INDEX] = blocknumber.to_le();
		let mut working_state = self.state.clone();
		for _ in 0..20 / 2 {
			Chacha::quarter_round(&mut working_state, 0, 4, 8, 12);
			Chacha::quarter_round(&mut working_state, 1, 5, 9, 13);
			Chacha::quarter_round(&mut working_state, 2, 6, 10, 14);
			Chacha::quarter_round(&mut working_state, 3, 7, 11, 15);
			Chacha::quarter_round(&mut working_state, 0, 5, 10, 15);
			Chacha::quarter_round(&mut working_state, 1, 6, 11, 12);
			Chacha::quarter_round(&mut working_state, 2, 7, 8, 13);
			Chacha::quarter_round(&mut working_state, 3, 4, 9, 14);
		}
		for i in 0..INNER_STATE_SIZE {
			working_state[i] = working_state[i].overflowing_add(self.state[i]).0;
			keystream[i * 4 + 0] = (working_state[i] & 0x000000ff) as u8;
			keystream[i * 4 + 1] = ((working_state[i] & 0x0000ff00) >> 8) as u8;
			keystream[i * 4 + 2] = ((working_state[i] & 0x00ff0000) >> 16) as u8;
			keystream[i * 4 + 3] = ((working_state[i] & 0xff000000) >> 24) as u8;
		}
	}

	pub fn get_next_keystream(&mut self, keystream: &mut [u8]) {
		let bn = u32::from_le(self.state[BLOCK_NUMBER_INDEX] + 1);
		return self.get_keystream(keystream, bn);
	}

	/// Resets the block number to zero.
	pub fn reset_block_counter(&mut self) {
		self.state[BLOCK_NUMBER_INDEX] = 0;
	}

	/// Performs a quarter round of chacha.
	//
	// Params:
	//  state = current working state for a block number
	//  a, b, c, d = constant of algorithm
	//
	fn quarter_round(state: &mut InnerState, a: usize, b: usize, c: usize, d: usize) {
		state[a] = state[a].overflowing_add(state[b]).0;
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(16);
		state[c] = state[c].overflowing_add(state[d]).0;
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(12);
		state[a] = state[a].overflowing_add(state[b]).0;
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(8);
		state[c] = state[c].overflowing_add(state[d]).0;
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(7);
	}
}

#[test]
fn reset_block_counter() {
	let mykey = vec![0; 32];
	let mynonce: Nonce = [0x00000000, 0x00000000, 0x0];
	let mut c = Chacha::new(&mykey, &mynonce);
	let mut keystream: [u8; 64] = [0; 64];
	c.get_keystream(&mut keystream, 5);
	assert_eq!(c.state[BLOCK_NUMBER_INDEX], 5);
	c.reset_block_counter();
	assert_eq!(c.state[BLOCK_NUMBER_INDEX], 0);
}