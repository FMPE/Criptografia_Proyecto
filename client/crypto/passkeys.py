"""Passkeys Ed25519 con challenge-response.

Pendiente (P1). Diseño previsto:
  - generate_keypair() -> (sk, pk) con nacl.signing.SigningKey.generate()
  - la llave privada se guarda como entrada cifrada dentro de la bóveda (bajo VK)
  - sign_challenge(sk, challenge) -> firma Ed25519 sobre el challenge de 32 B
"""
