// Copyright © 2021 siddharth ravikumar <s@ricketyspace.net>
// SPDX-License-Identifier: ISC

package challenge

import (
	"fmt"

	"ricketyspace.net/cryptopals/lib"
)

func C33() {
	p := `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`
	g := "2"

	bobDH, ok := lib.NewDH(p, g)
	if !ok {
		fmt.Printf("Error: Unable to initialize Bob's DH\n")
		return
	}
	bobPub := bobDH.Pub()

	aliceDH, ok := lib.NewDH(p, g)
	if !ok {
		fmt.Printf("Error: Unable to initialize Alice's DH\n")
		return
	}
	alicePub := aliceDH.Pub()

	fmt.Printf("Bob's Public Key: %v\n", bobPub)
	fmt.Printf("Alice's Public Key: %v\n", alicePub)

	bobSK := bobDH.SharedSecret(alicePub)
	aliceSK := aliceDH.SharedSecret(bobPub)

	fmt.Printf("Bob's Shared Secret: %v\n", bobSK)
	fmt.Printf("Alice's Shared Secret: %v\n", aliceSK)
}

// Output:
//
// Bob's Public Key: 1643885764635749905185286669845159934582084887082920484575736661857881413803716758104011553300289797471959856575142294320666171806270422042592899397481982112013553480536325274053314849714749476001273162892556993616487274390342051621320413728771423770530948406469330822402961546454873922957681133414376381132068675054467671469656879973048594626883621779920143513278275923717431617014815149122641914187619099986518437140853520703749892436895285769072311852719050868
// Alice's Public Key: 2117630372003291547304238942746013207937541182893404885360474505199490149232724788979332066198571834270965140264945165023039953933463201633113804032480311294273300738045023099614006411688026251922065963350957842553040777974959664992931644350472796129822014540265547001730793382895246979770486779123539760971314326080591746743952146527077274248561598014016801356783299256412567103348690878942546218165598511546303863615392999207407721968367448583928299961594067227
// Bob's Shared Secret: 1833663115948091203876591697977354917290093725402688631886160761642450349274139120294777688486566804565883401840101975178258685121386595677459542551170885092654203862535384314748874844668039849097403910982224132398888656574209620598758338572714699541434853656490180868196913263218863935920264792742959926191389742499235250227694421141817565112851829714974948024709190984742277041984774768964765367076029123820005229569505173960663876331721815448677542865838886305
// Alice's Shared Secret: 1833663115948091203876591697977354917290093725402688631886160761642450349274139120294777688486566804565883401840101975178258685121386595677459542551170885092654203862535384314748874844668039849097403910982224132398888656574209620598758338572714699541434853656490180868196913263218863935920264792742959926191389742499235250227694421141817565112851829714974948024709190984742277041984774768964765367076029123820005229569505173960663876331721815448677542865838886305
