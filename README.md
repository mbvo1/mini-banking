# Mini Banking: projeto de sistema seguro

Aplicação simples e funcional que implementa as decisões do documento
**"Projeto de Sistema Seguro: Internet Banking"**
O que o sistema faz: login (senha + código do autenticador), saldo, extrato,
transferência entre contas (com nova confirmação por código) e um log de
auditoria para o perfil de auditor.

> Projeto acadêmico.
> 
## Como rodar

Testado com Python 3.13; deve funcionar a partir do 3.10.

```bash
pip install -r requirements.txt
python run.py
```

Na primeira execução o `run.py` cria as chaves, um certificado TLS autoassinado e
três usuários de demonstração (`ana` e `bruno`, clientes, e `carla`, auditora).
**As senhas são geradas aleatoriamente e aparecem uma única vez no terminal**:
não existe senha padrão. Depois abra <https://localhost:8443>. O navegador avisa que
o certificado é autoassinado; isso é esperado em ambiente local.

O segundo fator é um código TOTP de 6 dígitos. Duas formas de obtê-lo:

- cadastrar o segredo mostrado no terminal em um app autenticador; ou
- só para a demonstração: `python -m app.tools code ana`.

Para apagar tudo e recomeçar: `python -m app.seed --reset`.

## Como mostrar que é seguro

```bash
python -m pytest -v
```

São 51 testes, que rodam em poucos segundos. Foram verificados também com
"falhas plantadas": ao desligar de propósito o MFA, o CSRF, o bloqueio por tentativas, a
checagem de perfil, o step-up, o contexto do AES-GCM, o encadeamento do log e a flag
HttpOnly do cookie, algum teste falhou em cada caso.

## Riscos do documento → proteção → teste

| Risco do documento | Proteção implementada | Testes (arquivo `tests/`) |
| --- | --- | --- |
| Phishing e engenharia social | MFA por TOTP; nova confirmação (step-up) em transferências. A criptografia sozinha não resolve phishing (Fórum 4) | `test_login_needs_password_and_mfa_code`, `test_transfer_needs_a_fresh_mfa_code` |
| Força bruta e credential stuffing | bcrypt, bloqueio de 15 min após 5 falhas, mensagem de erro única | `test_brute_force_locks_the_account_then_releases_it`, `test_login_error_is_the_same_for_every_failure`, `test_weak_passwords_are_rejected` |
| Senha fraca ou padrão (Fórum 1) | Política: mínimo de 12 caracteres, lista de senhas conhecidas, sem o usuário na senha; senhas de demonstração aleatórias | `test_weak_passwords_are_rejected`, `test_weak_passwords_cannot_create_users` |
| Interceptação (MITM) | HTTPS (TLS 1.3 negociado), cookie `Secure`, cabeçalho HSTS | `test_security_headers_and_cookie_flags` |
| Vazamento do banco | Senhas só como hash bcrypt; CPF, número da conta e segredo TOTP cifrados com AES-256-GCM; nada em texto claro no arquivo do banco | `test_database_has_no_plaintext_secrets`, `test_password_hash_is_bcrypt_and_salted` |
| Chaves expostas | Chaves em arquivo separado do banco (`secrets/keys.json`, permissão 600); nonce novo a cada cifragem | `test_database_has_no_plaintext_secrets`, `test_keys_are_stored_outside_database_with_restricted_permissions`, `test_aes_gcm_roundtrip_with_fresh_nonce_each_time` |
| Adulteração de dados | AES-GCM detecta alteração; saldo e transações têm selo HMAC-SHA-256; o texto cifrado é preso à sua linha (AAD) | `test_aes_gcm_detects_tampering`, `test_aes_gcm_binds_ciphertext_to_its_row`, `test_tampered_transaction_is_flagged`, `test_tampered_balance_is_flagged_and_blocks_transfers`, `test_tampered_ciphertext_is_handled_without_crashing` |
| Ameaça interna / acesso indevido | Perfis (cliente, auditor); nenhuma rota recebe id de conta, então cada cliente só vê a própria | `test_roles_limit_what_each_profile_can_open`, `test_customers_only_see_their_own_data` |
| Sessão roubada | Token aleatório guardado só como hash no servidor; logout e expiração por inatividade invalidam | `test_logout_invalidates_the_token_on_the_server`, `test_session_expires_after_idle_time` |
| CSRF | Token por sessão em todo POST autenticado; cookie `SameSite=Strict` | `test_transfer_without_valid_csrf_token_is_refused` |
| SQL injection e XSS | Consultas parametrizadas; templates com escape automático; CSP restritiva | `test_sql_injection_in_login_does_not_work`, `test_user_supplied_text_is_escaped_against_xss` |
| Apagar rastros | Log de auditoria encadeado por SHA-256: editar ou remover um registro do meio quebra a cadeia | `test_audit_chain_is_valid_until_someone_edits_it`, `test_audit_chain_detects_a_deleted_entry` |
| Erros de cripto da aula (algoritmo próprio, MD5, chave no código) | Só bibliotecas padrão (`bcrypt`, `cryptography`); o único código "à mão" é o TOTP, testado com os vetores do RFC 6238 | `test_totp_matches_rfc6238_test_vectors`, `test_bcrypt_cost_in_production_is_at_least_12` |

## Onde cada coisa está

```
app/security.py   bcrypt, AES-256-GCM, HMAC-SHA-256, TOTP, política de senha, chaves
app/db.py         esquema SQLite, transações e log de auditoria encadeado
app/service.py    login com MFA e bloqueio, sessões, extrato, transferência
app/main.py       rotas, CSRF, cookies e cabeçalhos de segurança
app/seed.py       usuários de demonstração (senhas aleatórias)
app/tools.py      só para demo: mostra o código TOTP atual
app/make_cert.py  certificado TLS autoassinado (ECDSA P-256)
run.py            sobe tudo em https://localhost:8443
tests/            51 testes de segurança
```

