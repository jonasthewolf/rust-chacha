

mod chacha {

// Type of inner state of chacha
const inner_state_size : usize = 16;
type inner_state = [u32;inner_state_size];

// Type of nonce
const nonce_length : usize = 3;
type nonce = [u32;nonce_length];

// Alias for generated keystream block
type keystream_block = [u8;inner_state_size];

// Index of block number
const block_number_index : usize = 12;


// Structure for chacha algorithm
pub struct Chacha {
	// The state
	state : inner_state
}

fn as_le(a : [u8;4]) -> u32 {
	(((a[0] as u32) << 24) | ((a[1] as u32) << 16) | ((a[2] as u32) << 8) | ((a[3] as u32) << 0)) as u32
}

impl Chacha {
	pub fn new(k : [u8;256/8], n : nonce) -> Chacha {
		Chacha {
			state : [ 0x65787061u32.to_le(),
			          0x6e642033u32.to_le(),
			          0x322d6279u32.to_le(),
			          0x7465206bu32.to_le(),
					  as_le(k[0..4]),
					  as_le(k[4..8]),
					  as_le(k[8..12]),
					  as_le(k[12..16]),
					  0, 0, 0, 0 /* BN */, n[0], n[1], n[2], 0 ],
		}
	}

    /**
     * Generates a block of key stream for the given block number
     *
     * Params:
     *   keystream = at least 64 bytes of memory for the generated key stream
     *   blocknumber = the blocknumber to generate the keystream for
     *
     */
	fn get_keystream(&mut self, keystream : keystream_block, blocknumber : u32) {
		self.state[block_number_index] = blocknumber;
		let mut working_state = self.state.clone();
		for _ in 0 .. 20/2 {
			Chacha::quarter_round(working_state, 0, 4, 8, 12);
			Chacha::quarter_round(working_state, 1, 5, 9, 13);
			Chacha::quarter_round(working_state, 2, 6, 10, 14);
			Chacha::quarter_round(working_state, 3, 7, 11, 15);
			Chacha::quarter_round(working_state, 0, 5, 10, 15);
			Chacha::quarter_round(working_state, 1, 6, 11, 12);
			Chacha::quarter_round(working_state, 2, 7, 8, 13);
			Chacha::quarter_round(working_state, 3, 4, 9, 14);
		}
		working_state.iter_mut().zip(self.state.iter()).map(|(a, &b)| *a + b);
		//working_state += state;
		//self.serialize_inner_state(keystream, working_state);
	}
/*
	fn get_next_keystream(&mut self, keystream : keystream_block) {
		return self.get_keystream(keystream, self.state[block_number_index] + 1);
	}
*/	
    /** Resets the block number to zero. */
	fn reset_block_counter(&mut self) {
		self.state[block_number_index] = 0;
	}

    /** Copies the key into the state. */
	fn set_key(&mut self,  usedkey : [u8;256/8]) {
		for i in usedkey.iter() {
	//		self.state[4 + i] = usedkey[i];
	    }
	}

    /** Sets the nonce in the state. */
	fn set_nonce(&mut self, n : nonce) {
		self.state[13] = n[0];
	    self.state[14] = n[1];
	    self.state[15] = n[2];
	}

    /** 
     * Performs a quarter round of chacha. 
     * 
     * Params:
     *  state = current working state for a block number
     *  a, b, c, d = constant of algorithm
     *
     */
	fn quarter_round(mut state : inner_state, a : usize, b : usize, c : usize, d : usize) {
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(16);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(12);
		state[a] += state[b];
		state[d] ^= state[a];
		state[d] = state[d].rotate_left(8);
		state[c] += state[d];
		state[b] ^= state[c];
		state[b] = state[b].rotate_left(7);
    }

	/** Copy resulting key stream as little endian to receiving buffer. */	
	fn serialize_inner_state(keystream : keystream_block, state : inner_state) {
		for (i, s) in state.iter().enumerate() {
			//keystream[(i*4)..(i*4+4)] = nativeToLittleEndian(state[i]);
		}
	}
	
}
}

