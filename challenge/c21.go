// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C21() {
	mt := new(lib.MTRand)
	for {
		fmt.Printf("%v\n", mt.Extract())
	}
}

// Output:
// cryptopals -c 21  | dieharder -a -g 013
// #=============================================================================#
// #            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
// #=============================================================================#
//    rng_name    |rands/second|   Seed   |
//         mt19937|  3.66e+07  | 657918460|
// #=============================================================================#
//         test_name   |ntup| tsamples |psamples|  p-value |Assessment
// #=============================================================================#
//    diehard_birthdays|   0|       100|     100|0.95711193|  PASSED
//       diehard_operm5|   0|   1000000|     100|0.34504882|  PASSED
//   diehard_rank_32x32|   0|     40000|     100|0.71335532|  PASSED
//     diehard_rank_6x8|   0|    100000|     100|0.65462930|  PASSED
//    diehard_bitstream|   0|   2097152|     100|0.27707943|  PASSED
//         diehard_opso|   0|   2097152|     100|0.61472493|  PASSED
//         diehard_oqso|   0|   2097152|     100|0.84679724|  PASSED
//          diehard_dna|   0|   2097152|     100|0.97257921|  PASSED
// diehard_count_1s_str|   0|    256000|     100|0.84643965|  PASSED
// diehard_count_1s_byt|   0|    256000|     100|0.58411043|  PASSED
//  diehard_parking_lot|   0|     12000|     100|0.18589551|  PASSED
//     diehard_2dsphere|   2|      8000|     100|0.99077799|  PASSED
//     diehard_3dsphere|   3|      4000|     100|0.46587675|  PASSED
//      diehard_squeeze|   0|    100000|     100|0.61721980|  PASSED
//         diehard_sums|   0|       100|     100|0.65717928|  PASSED
//         diehard_runs|   0|    100000|     100|0.87523693|  PASSED
//         diehard_runs|   0|    100000|     100|0.62948193|  PASSED
//        diehard_craps|   0|    200000|     100|0.88522406|  PASSED
//        diehard_craps|   0|    200000|     100|0.44258302|  PASSED
//  marsaglia_tsang_gcd|   0|  10000000|     100|0.29057775|  PASSED
//  marsaglia_tsang_gcd|   0|  10000000|     100|0.24578249|  PASSED
//          sts_monobit|   1|    100000|     100|0.93118860|  PASSED
//             sts_runs|   2|    100000|     100|0.65793436|  PASSED
//           sts_serial|   1|    100000|     100|0.57407505|  PASSED
//           sts_serial|   2|    100000|     100|0.00431706|   WEAK
//           sts_serial|   3|    100000|     100|0.35776534|  PASSED
//           sts_serial|   3|    100000|     100|0.96521325|  PASSED
//           sts_serial|   4|    100000|     100|0.31817641|  PASSED
//           sts_serial|   4|    100000|     100|0.89678471|  PASSED
//           sts_serial|   5|    100000|     100|0.78570780|  PASSED
//           sts_serial|   5|    100000|     100|0.99714600|   WEAK
//           sts_serial|   6|    100000|     100|0.92511559|  PASSED
//           sts_serial|   6|    100000|     100|0.38468623|  PASSED
//           sts_serial|   7|    100000|     100|0.78028024|  PASSED
//           sts_serial|   7|    100000|     100|0.65634177|  PASSED
//           sts_serial|   8|    100000|     100|0.97601180|  PASSED
//           sts_serial|   8|    100000|     100|0.68382603|  PASSED
//           sts_serial|   9|    100000|     100|0.40071117|  PASSED
//           sts_serial|   9|    100000|     100|0.41034914|  PASSED
//           sts_serial|  10|    100000|     100|0.39639808|  PASSED
//           sts_serial|  10|    100000|     100|0.93997377|  PASSED
//           sts_serial|  11|    100000|     100|0.31779932|  PASSED
//           sts_serial|  11|    100000|     100|0.07049939|  PASSED
//           sts_serial|  12|    100000|     100|0.28219401|  PASSED
//           sts_serial|  12|    100000|     100|0.76959174|  PASSED
//           sts_serial|  13|    100000|     100|0.89979957|  PASSED
//           sts_serial|  13|    100000|     100|0.96954492|  PASSED
//           sts_serial|  14|    100000|     100|0.15264111|  PASSED
//           sts_serial|  14|    100000|     100|0.31132632|  PASSED
//           sts_serial|  15|    100000|     100|0.05821586|  PASSED
//           sts_serial|  15|    100000|     100|0.54660467|  PASSED
//           sts_serial|  16|    100000|     100|0.81512002|  PASSED
//           sts_serial|  16|    100000|     100|0.56644697|  PASSED
//          rgb_bitdist|   1|    100000|     100|0.01331870|  PASSED
//          rgb_bitdist|   2|    100000|     100|0.82050170|  PASSED
//          rgb_bitdist|   3|    100000|     100|0.85095344|  PASSED
//          rgb_bitdist|   4|    100000|     100|0.23080696|  PASSED
//          rgb_bitdist|   5|    100000|     100|0.76551214|  PASSED
//          rgb_bitdist|   6|    100000|     100|0.17295792|  PASSED
//          rgb_bitdist|   7|    100000|     100|0.84890262|  PASSED
//          rgb_bitdist|   8|    100000|     100|0.67753432|  PASSED
//          rgb_bitdist|   9|    100000|     100|0.41315091|  PASSED
//          rgb_bitdist|  10|    100000|     100|0.92332751|  PASSED
//          rgb_bitdist|  11|    100000|     100|0.24336716|  PASSED
//          rgb_bitdist|  12|    100000|     100|0.83781776|  PASSED
// rgb_minimum_distance|   2|     10000|    1000|0.64093266|  PASSED
// rgb_minimum_distance|   3|     10000|    1000|0.28329190|  PASSED
// rgb_minimum_distance|   4|     10000|    1000|0.77117519|  PASSED
// rgb_minimum_distance|   5|     10000|    1000|0.13513713|  PASSED
//     rgb_permutations|   2|    100000|     100|0.82339487|  PASSED
//     rgb_permutations|   3|    100000|     100|0.97274943|  PASSED
//     rgb_permutations|   4|    100000|     100|0.45512642|  PASSED
//     rgb_permutations|   5|    100000|     100|0.99466930|  PASSED
//       rgb_lagged_sum|   0|   1000000|     100|0.83150881|  PASSED
//       rgb_lagged_sum|   1|   1000000|     100|0.04946850|  PASSED
//       rgb_lagged_sum|   2|   1000000|     100|0.54335098|  PASSED
//       rgb_lagged_sum|   3|   1000000|     100|0.99671599|   WEAK
//       rgb_lagged_sum|   4|   1000000|     100|0.44020347|  PASSED
//       rgb_lagged_sum|   5|   1000000|     100|0.43222741|  PASSED
//       rgb_lagged_sum|   6|   1000000|     100|0.52186775|  PASSED
//       rgb_lagged_sum|   7|   1000000|     100|0.24269588|  PASSED
//       rgb_lagged_sum|   8|   1000000|     100|0.23375901|  PASSED
//       rgb_lagged_sum|   9|   1000000|     100|0.83545719|  PASSED
//       rgb_lagged_sum|  10|   1000000|     100|0.11948118|  PASSED
//       rgb_lagged_sum|  11|   1000000|     100|0.03349326|  PASSED
//       rgb_lagged_sum|  12|   1000000|     100|0.61767552|  PASSED
//       rgb_lagged_sum|  13|   1000000|     100|0.99634756|   WEAK
//       rgb_lagged_sum|  14|   1000000|     100|0.93673033|  PASSED
//       rgb_lagged_sum|  15|   1000000|     100|0.07611242|  PASSED
//       rgb_lagged_sum|  16|   1000000|     100|0.88447164|  PASSED
//       rgb_lagged_sum|  17|   1000000|     100|0.03888719|  PASSED
//       rgb_lagged_sum|  18|   1000000|     100|0.28873646|  PASSED
//       rgb_lagged_sum|  19|   1000000|     100|0.88421163|  PASSED
//       rgb_lagged_sum|  20|   1000000|     100|0.46038906|  PASSED
//       rgb_lagged_sum|  21|   1000000|     100|0.81182182|  PASSED
//       rgb_lagged_sum|  22|   1000000|     100|0.39720274|  PASSED
//       rgb_lagged_sum|  23|   1000000|     100|0.30703737|  PASSED
//       rgb_lagged_sum|  24|   1000000|     100|0.86031549|  PASSED
//       rgb_lagged_sum|  25|   1000000|     100|0.99886093|   WEAK
//       rgb_lagged_sum|  26|   1000000|     100|0.86928859|  PASSED
//       rgb_lagged_sum|  27|   1000000|     100|0.46656327|  PASSED
//       rgb_lagged_sum|  28|   1000000|     100|0.99931707|   WEAK
//       rgb_lagged_sum|  29|   1000000|     100|0.99990121|   WEAK
//       rgb_lagged_sum|  30|   1000000|     100|0.61131381|  PASSED
//       rgb_lagged_sum|  31|   1000000|     100|0.22630230|  PASSED
//       rgb_lagged_sum|  32|   1000000|     100|0.42803610|  PASSED
//      rgb_kstest_test|   0|     10000|    1000|0.45199651|  PASSED
//      dab_bytedistrib|   0|  51200000|       1|0.45649445|  PASSED
//              dab_dct| 256|     50000|       1|0.18482516|  PASSED
//         dab_filltree|  32|  15000000|       1|0.50412510|  PASSED
//         dab_filltree|  32|  15000000|       1|0.46565944|  PASSED
//        dab_filltree2|   0|   5000000|       1|0.17966614|  PASSED
//        dab_filltree2|   1|   5000000|       1|0.36272804|  PASSED
//         dab_monobit2|  12|  65000000|       1|0.43316604|  PASSED
