// ========================== Модуль whitelist/verifier ===================================
//   rDNS + fDNS верификация легитимных ботов (Googlebot, Bingbot и др.).
//   Fake bot penalty: UA совпадает с легитимным ботом, DNS-верификация провалена.
//
//   ЧТО ЗДЕСЬ:
//     - Verify(ip, ua) — reverse DNS (PTR) + forward DNS (A/AAAA) верификация
//     - Fake bot detection → fake_bot flag → +35 к score
//
//   Реализуется в Task 3.2 и Task 3.5.

package whitelist
