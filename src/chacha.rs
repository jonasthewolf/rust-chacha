

mod chacha {

// Type of inner state of chacha
const inner_state_size : usize = 16;
type inner_state = [u32;inner_state_size];

// Type of nonce
const nonce_length : usize = 3;
type nonce = [u32;nonce_length];

// Alias for generated keystream block
use keystream_block as u8[inner_state_size];

/// Structure for chacha algorithm
struct Chacha<usize rounds, alias k> {
	static_assert!(rounds % 2 == 0);  // Number of rounds has to be even.
	/// Index of block number
	const block_number_index : usize = 12;
	/// The state
	inner_state state;
}

impl Chacha {
	 this(ref const k usedkey, ref const nonce n) {
		state[0] = littleEndianToNative!(uint,4u)([0x65u, 0x78u, 0x70u, 0x61u]);
		state[1] = littleEndianToNative!(uint,4u)([0x6eu, 0x64u, 0x20u, 0x33u]);
		state[2] = littleEndianToNative!(uint,4u)([0x32u, 0x2du, 0x62u, 0x79u]);
		state[3] = littleEndianToNative!(uint,4u)([0x74u, 0x65u, 0x20u, 0x6bu]);
	    
	    reset_block_counter();
	    set_key(usedkey);
	    set_nonce(n);
	}

    /**
     * Generates a block of key stream for the given block number
     *
     * Params:
     *   keystream = at least 64 bytes of memory for the generated key stream
     *   blocknumber = the blocknumber to generate the keystream for
     *
     */
	fn get_keystream(ref keystream_block keystream, uint blocknumber) {
		state[block_number_index] = blocknumber;
		auto working_state = state;
		for (int i = 0; i < rounds/2; ++i) {
			quarter_round(working_state, 0u, 4u, 8u, 12u);
			quarter_round(working_state, 1u, 5u, 9u, 13u);
			quarter_round(working_state, 2u, 6u, 10u, 14u);
			quarter_round(working_state, 3u, 7u, 11u, 15u);
			quarter_round(working_state, 0u, 5u, 10u, 15u);
			quarter_round(working_state, 1u, 6u, 11u, 12u);
			quarter_round(working_state, 2u, 7u, 8u, 13u);
			quarter_round(working_state, 3u, 4u, 9u, 14u);
		}
		working_state[] += state[];
		serialize_inner_state(keystream, working_state);
	}

	fn get_next_keystream(ref keystream_block keystream) {
		return get_keystream(keystream, state[block_number_index] + 1);
	}
	
    /** Resets the block number to zero. */
	fn reset_block_counter() {
		state[block_number_index] = 0;
	}

    /** Copies the key into the state. */
	fn set_key(const ref k usedkey) {
		for (auto i = 0; i < usedkey.get_key_length(); i++) {
	    	state[4+i] = usedkey.get_key_bits()[i];
	    }
	}

    /** Sets the nonce in the state. */
	fn set_nonce(const ref nonce n) {
		state[13] = n[0];
	    state[14] = n[1];
	    state[15] = n[2];
	}

    /** 
     * Performs a quarter round of chacha. 
     * 
     * Params:
     *  state = current working state for a block number
     *  a, b, c, d = constant of algorithm
     *
     */
	fn quarter_round(ref inner_state state, immutable size_t a, immutable size_t b,
			immutable size_t c, immutable size_t d) {
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
	fn serialize_inner_state(ref keystream_block keystream, inner_state state) {
		for (int i = 0; i < state.length; i++) {
			keystream[(i*4)..(i*4+4)] = nativeToLittleEndian(state[i]);
		}
	}
	
}

}
