use crate::{BashHash, OutputSize};
use core::ops::Add;
use digest::{
    array::ArraySize,
    block_buffer::BlockBuffer,
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Sum, U0, U192},
};

impl<OS: OutputSize> SerializableState for BashHash<OS>
where
    U192: Add<OS::BlockSize>,
    OS::BlockSize: Add<U0>,
    Sum<U192, OS::BlockSize>: ArraySize,
    Sum<OS::BlockSize, U0>: ArraySize,
{
    type SerializedStateSize = Sum<U192, OS::BlockSize>;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut res = SerializedState::<Self>::default();
        let (core_dst, buf_dst) = res.split_at_mut(192);
        core_dst.copy_from_slice(&self.core.serialize());
        buf_dst.copy_from_slice(&self.buffer.serialize());
        res
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_core, serialized_buf) = serialized_state.split_at(192);

        let core = SerializableState::deserialize(serialized_core.try_into().unwrap())?;
        let buffer = BlockBuffer::deserialize(serialized_buf.try_into().unwrap())
            .map_err(|_| DeserializeStateError)?;

        Ok(Self { core, buffer })
    }
}
