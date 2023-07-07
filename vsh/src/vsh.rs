
use bitvec::prelude::*;
use num::bigint::BigUint;

const PRIME_NUMBERS: &[u16] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
    401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
    631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
    751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,
    1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303,
    1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543,
    1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627,
    1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753,
    1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
    1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
    2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239,
    2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
    2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447,
    2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593,
    2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699,
    2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
    2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927,
    2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
    3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203,
    3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323,
    3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457,
    3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557,
    3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671,
];

const RSA_TEN_TWENTY_FOUR: &str = "135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563";
const BLOCK_SIZE: u8 = 64;

pub fn validate_and_pad_input(input: Vec<u8>) -> Result<Vec<u8>, String> {
    let input_length = input.len() as u8;

    if input_length == 0 {
        return Err(String::from("Failed to hash, can't hash without data."));
    }

    let padded_data = if input_length % BLOCK_SIZE == 0 {
        input
    } else {
        let zeros_to_pad = BLOCK_SIZE - (input_length % BLOCK_SIZE);
        let zeros = vec![0; zeros_to_pad as usize];
        [input.as_slice(), &zeros].concat()
    };

    Ok(padded_data)
}


pub fn get_prime_numbers() -> Vec<u16> {
    PRIME_NUMBERS.to_vec()
}

fn reverse_chunks_by_block_size(data: &[u8]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();

    
    for i in (0..data.len()).rev().step_by(BLOCK_SIZE as usize) {
        let start_idx = if i < BLOCK_SIZE as usize - 1 {
            0
        } else {
            i - (BLOCK_SIZE as usize - 1)
        };

        let end_idx = i + 1;
        let chunk = &data[start_idx..end_idx];
        chunks.push(chunk.to_vec());
    }
    chunks
}

pub fn calculate_vhs_of_x(input: Vec<u8>) -> Vec<usize> {
    // println!("input len:{:?} bl: {:?}", input_length, block_len);
    let chunks = reverse_chunks_by_block_size(&input);
    let mut set_bits: Vec<usize> = vec![];
    for chunk in chunks {
        let bits = chunk.view_bits::<Msb0>();
        // println!("bits:{:?}", bits);
        set_bits = bits
            .iter()
            .enumerate()
            .filter(|(_, b)| **b)
            .map(|(i, _)| (8 * BLOCK_SIZE as usize) - i)
            .collect();
        // println!("Bits one: {:?}", set_bits);
    }
    set_bits
}

pub fn get_prime_list(index:Vec<usize>) -> Vec<u128> {
    let primes = get_prime_numbers();
    let mut prime_list: Vec<u16> = vec![];

    for a_index in index {
        prime_list.push(primes[a_index-1]);
    }
    // println!("Prime list:{:?}",prime_list);
    
    let mut prime_products = vec![1];
    for a_prime in prime_list {
        let second_prime: Vec<u128> = vec![a_prime as u128];
        prime_products = get_prime_products(&prime_products, &second_prime);
        // println!("Prime prod:{:?}",prime_products);
    }
    prime_products
}

pub fn do_mod_with_products(product: Vec<u128>) -> BigUint{

    let modulus_str = RSA_TEN_TWENTY_FOUR;
    let modulus: BigUint = BigUint::parse_bytes(modulus_str.as_bytes(), 10).unwrap();

    let bytes: Vec<u8> = product.iter()
        .flat_map(|&x| x.to_le_bytes().to_vec())
        .collect();
    let num = BigUint::from_bytes_le(&bytes);
    // println!("Num is:{:?} modulus is: {:?}", num, modulus);
    let remainder = num % modulus;
    println!("{:?}", remainder);
    remainder
}



pub fn get_prime_products(x: &Vec<u128>, y: &Vec<u128>) -> Vec<u128> {
    let n = x.len();
    let mut result = vec![0; n * 2];
    
    if n <= 4 {
        for i in 0..n {
            for j in 0..n {
                result[i + j] += x[i] * y[j];
            }
        }
    } else {
        let mid = n / 2;
        
        let xl = x[0..mid].to_vec();
        let xr = x[mid..].to_vec();
        let yl = y[0..mid].to_vec();
        let yr = y[mid..].to_vec();
        
        let p1 = get_prime_products(&xl, &yl);
        let p2 = get_prime_products(&xr, &yr);
        let mut xl_xr = xl.clone();
        for i in 0..mid {
            xl_xr[i] += xr[i];
        }
        let mut yl_yr = yl.clone();
        for i in 0..mid {
            yl_yr[i] += yr[i];
        }
        let p3 = get_prime_products(&xl_xr, &yl_yr);
        
        for i in 0..n {
            result[i] += p1[i];
            result[i + n] += p2[i];
            result[i + mid] += p3[i] - p1[i] - p2[i];
        }
    }
    
    while result.len() > 1 && result.last() == Some(&0) {
        result.pop();
    }
    
    result
}