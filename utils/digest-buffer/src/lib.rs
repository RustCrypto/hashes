#![no_std]
extern crate byte_tools;
extern crate generic_array;
use generic_array::{GenericArray, ArrayLength};
use byte_tools::{copy_memory, zero};

#[derive(Clone, Copy)]
pub struct DigestBuffer<N: ArrayLength<u8>> where N::ArrayType: Copy {
    buffer: GenericArray<u8, N>,
    buffer_idx: usize,
}

impl <N: ArrayLength<u8>> DigestBuffer<N> where N::ArrayType: Copy {
    pub fn new() -> DigestBuffer<N> {
        DigestBuffer::<N> {
            buffer: GenericArray::new(),
            buffer_idx: 0,
        }
    }

    pub fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
        let mut i = 0;
        let size = self.size();
        // If there is already data in the buffer, copy as much as we can
        // into it and process the data if the buffer becomes full.
        if self.buffer_idx != 0 {
            let buffer_remaining = size - self.buffer_idx;
            if input.len() >= buffer_remaining {
                    copy_memory(
                        &input[..buffer_remaining],
                        &mut self.buffer[self.buffer_idx..size]);
                self.buffer_idx = 0;
                func(&self.buffer);
                i += buffer_remaining;
            } else {
                copy_memory(
                    input,
                    &mut self.buffer[self.buffer_idx..][..input.len()]);
                self.buffer_idx += input.len();
                return;
            }
        }

        // While we have at least a full buffer size chunks's worth of data,
        // process that data without copying it into the buffer
        while input.len() - i >= size {
            func(&input[i..i + size]);
            i += size;
        }

        // Copy any input data into the buffer. At this point in the method,
        // the ammount of data left in the input vector will be less than
        // the buffer size and the buffer will be empty.
        let input_remaining = input.len() - i;
        copy_memory(
            &input[i..],
            &mut self.buffer[0..input_remaining]);
        self.buffer_idx += input_remaining;
    }

    pub fn reset(&mut self) {
        self.buffer_idx = 0;
    }

    pub fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.buffer_idx);
        zero(&mut self.buffer[self.buffer_idx..idx]);
        self.buffer_idx = idx;
    }

    pub fn next(&mut self, len: usize) -> &mut [u8] {
        self.buffer_idx += len;
        &mut self.buffer[self.buffer_idx - len..self.buffer_idx]
    }

    pub fn full_buffer(& mut self) -> &[u8] {
        assert!(self.buffer_idx == self.size());
        self.buffer_idx = 0;
        &self.buffer[..]
    }

    pub fn current_buffer(&mut self) -> &[u8] {
        let tmp = self.buffer_idx;
        self.buffer_idx = 0;
        &self.buffer[..tmp]
    }

    pub fn position(&self) -> usize { self.buffer_idx }

    pub fn remaining(&self) -> usize { self.size() - self.buffer_idx }

    pub fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }

    pub fn size(&self) -> usize {
         N::to_usize()
    }
}

impl <N: ArrayLength<u8>> Default for DigestBuffer<N> where N::ArrayType: Copy {
    fn default() -> Self { Self::new() }
}
