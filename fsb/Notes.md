Notes on the progress of the FSB crate: 
- [x] Make the selections of bits

- [x] Shift bits in Rust. Straight forward if we are working with a number with as many
bits as its underlying structure (e.g. a number of 8 bits for a u8 integer). However, when
that is not the case, it seems we'll need to do some additional functions. Check whether
there exists work in this front. 

- [x] Create the full logic of processing the compression

The idea behind the hash algorithm is simple. What seems to be more complex is how to
handle the definition of the function, following the ideas presented in the other crates.


So we've create all the processing of the blocks. Now we need to organise the domain
extender with the padding. Important! S - R is always divisible by 8.

WORK ON THE PADDING, it is a dissaster the code now. (25 October 2020) The padding seems
to be working, but looks ugly. Certain there are better ways to handle the
padding. Give it another try before starting to put the pieces together.   

- [ ] Handle the entry of the message. Follow existing crates on how to 
transform the message into arrays.
  - [ ] Define what is the information that the hasher needs to know at each iteration 
  (appart from the buffer). 
  - [ ] Define the functions of the digest, in particular, consider the `default`, `update`
  and `finalise`. For now, taking as a reference the [Whirpool][1] implementation. 
 

[1]: https://github.com/RustCrypto/hashes/tree/master/whirlpool