#![no_std]

use aes_ctr::{Aes128Ctr, Aes256Ctr};

cipher::new_sync_test!(aes128_ctr_core, Aes128Ctr, "aes128-ctr");
cipher::new_sync_test!(aes256_ctr_core, Aes256Ctr, "aes256-ctr");
cipher::new_seek_test!(aes128_ctr_seek, Aes128Ctr);
cipher::new_seek_test!(aes256_ctr_seek, Aes256Ctr);
