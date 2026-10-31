# 404sec Rate Limiter

**Basic Rate Limiting & Anti-Flood Protection**  
Coded by **404sec**

Outil simple de rate limiting en Python + exemple de configuration Nginx pour limiter le flood de requêtes.

> Ceci n'est **pas** une protection anti-DDoS professionnelle.  
> Pour une vraie protection, utilise **Cloudflare** (recommandé).

---

## Fonctionnalités

- Rate limiting par IP (fenêtre glissante)
- Ban temporaire des IP abusives
- Whitelist d'IP
- Logs des IP bloquées
- Endpoint `/stats`
- Exemple de configuration Nginx inclus

---

## Installation

```bash
git clone https://github.com/TON_PSEUDO/404sec-rate-limiter.git
cd 404sec-rate-limiter
pip install -r requirements.txt