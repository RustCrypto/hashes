use core::mem::transmute_copy;

#[cfg(target_endian = "little")]
pub(crate) static TABLES: [[u64; 256]; 4] = unsafe { transmute_copy(include_bytes!("tables.bin")) };

#[cfg(target_endian = "big")]
pub(crate) static TABLES: [[u64; 256]; 4] = {
    let mut tables: [[u64; 256]; 4] = unsafe { transmute_copy(include_bytes!("tables.bin")) };
    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 256 {
            tables[i][j] = tables[i][j].swap_bytes();
            j += 1;
        }
        i += 1;
    }
    tables
};
