Notes on the progress of the FSB crate: 

- [ ] Handle the entry of the message. Follow existing crates on how to 
transform the message into arrays.
  - [ ] Define what is the information that the hasher needs to know at each iteration 
  (appart from the buffer). 
  - [ ] Define the functions of the digest, in particular, consider the `default`, `update`
  and `finalise`. For now, taking as a reference the [Whirpool][1] implementation. 

- [ ] Make the selections of bits

- [ ] Shift bits in Rust. Straight forward if we are working with a number with as many
bits as its underlying structure (e.g. a number of 8 bits for a u8 integer). However, when
that is not the case, it seems we'll need to do some additional functions. Check whether
there exists work in this front. 

The idea behind the hash algorithm is simple. What seems to be more complex is how to
handle the definition of the function, following the ideas presented in the other crates.

[1]: https://github.com/RustCrypto/hashes/tree/master/whirlpool