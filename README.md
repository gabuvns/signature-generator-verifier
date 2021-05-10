# signature-generator-verifier
RSA Signature Generator and Verifier made with python 

## TODO
- [x] Gerar chave (mínimo de 1024 bits);
  - Escolher 2 primos distintos `p`, `q`;
  - Calcular `n = pq`;
  - Calcular `λ(n) = lcm(p − 1, q − 1)`;
  - Escolher `e`, tal que `1 <= e <= λ(n)`;
  > Podemos escolher `e = 65537` (fatorização de Fermat);
  - Calcular `d`, tal que `d*e mod λ(n) = 1`;
  > Chave publica é `(n, e)`;
      
  > Chave privada é `(n, d)`;
  
  > Cifrar mensagem m: `c(m) = m^e mod n`;
  
  > Decifrar mensagem m: `m(c) = c^d mod n`;

- [ ] Formatar mensagem m (*padding* OAEP);

- [x] Assinar mensagem (fazer *digest* da mensagem com SHA-3).
  - `s = m^d mod n`;

- [x] Desformatar mensagem m;

- [x] Ler mensagem de arquivo;
- [x] Salvar texto cifrado em arquivo;
- [x] Salvar texto decifrado em arquivo;