macro_rules! compress {
    ($x:expr, $a:expr, $b:expr, $c:expr) => {
        // save state
        let aa = $a;
        let bb = $b;
        let cc = $c;

        pass!($x, $a, $b, $c, 5);
        key_schedule!($x);
        pass!($x, $c, $a, $b, 7);
        key_schedule!($x);
        pass!($x, $b, $c, $a, 9);

        // feed forward
        $a ^= aa;
        $b -= bb;
        $c += cc;
    }
}

macro_rules! pass {
    ($x:expr, $a:expr, $b:expr, $c:expr, $mul:expr) => {
        round!($a, $b, $c, $x[0], $mul);
        round!($b, $c, $a, $x[1], $mul);
        round!($c, $a, $b, $x[2], $mul);
        round!($a, $b, $c, $x[3], $mul);
        round!($b, $c, $a, $x[4], $mul);
        round!($c, $a, $b, $x[5], $mul);
        round!($a, $b, $c, $x[6], $mul);
        round!($b, $c, $a, $x[7], $mul);
    }
}

macro_rules! round {
    ($a:expr, $b:expr, $c:expr, $xor:expr, $mul:expr) => {
        $c ^= $xor;
        $a -= wrapped!(T1[s_index!($c, 0)] ^ T2[s_index!($c, 2)] ^
                       T3[s_index!($c, 4)] ^ T4[s_index!($c, 6)] );
        $b += wrapped!(T4[s_index!($c, 1)] ^ T3[s_index!($c, 3)] ^
                       T2[s_index!($c, 5)] ^ T1[s_index!($c, 7)] );
        $b *= wrapped!($mul);
    }
}

macro_rules! wrapped {
    ($n:expr) => {
        Wrapping($n)
    }
}

macro_rules! s_index {
    ($c:expr, $pos:expr) => {
        (($c >> ($pos * 8)).0 & 0xFF) as usize
    }
}

macro_rules! key_schedule {
    ($x:expr) => {
        $x[0] -= $x[7] ^ wrapped!(0xA5A5A5A5A5A5A5A5);
        $x[1] ^= $x[0];
        $x[2] += $x[1];
        $x[3] -= $x[2] ^ (!$x[1] << 19);
        $x[4] ^= $x[3];
        $x[5] += $x[4];
        $x[6] -= $x[5] ^ (!$x[4] >> 23);
        $x[7] ^= $x[6];
        $x[0] += $x[7];
        $x[1] -= $x[0] ^ (!$x[7] << 19);
        $x[2] ^= $x[1];
        $x[3] += $x[2];
        $x[4] -= $x[3] ^ (!$x[2] >> 23);
        $x[5] ^= $x[4];
        $x[6] += $x[5];
        $x[7] -= $x[6] ^ wrapped!(0x0123456789ABCDEF);
    }
}
