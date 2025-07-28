# Vantus - Sistema de Login Seguro

Sistema de autenticação seguro desenvolvido em Python com Flask, projetado para ser hospedado em VPS Ubuntu.

## 🛡️ Recursos de Segurança

- **Criptografia bcrypt** para senhas
- **Proteção contra força bruta** com bloqueio temporário
- **Logs de segurança** detalhados
- **Validação de senhas** fortes
- **Headers de segurança** configurados
- **Proteção CSRF** integrada
- **Monitoramento de IP** e User-Agent
- **Sessões seguras** com cookies HTTPOnly

## 🚀 Tecnologias

- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Frontend**: Bootstrap 5, Font Awesome
- **Segurança**: bcrypt, JWT, cryptography
- **Produção**: Gunicorn, Nginx, Supervisor
- **Banco**: SQLite (desenvolvimento) / PostgreSQL (produção)

## 📦 Instalação

### Desenvolvimento Local

1. **Clone o repositório**
```bash
git clone https://github.com/vinieves/vantus.git
cd vantus
```

2. **Crie ambiente virtual**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows
```

3. **Instale dependências**
```bash
pip install -r requirements.txt
```

4. **Configure variáveis de ambiente**
```bash
# Crie arquivo .env
SECRET_KEY=sua-chave-secreta-aqui
JWT_SECRET_KEY=sua-chave-jwt-aqui
DATABASE_URL=sqlite:///vantus.db
```

5. **Execute a aplicação**
```bash
python app.py
```

### Produção (VPS Ubuntu)

1. **Execute o script de deploy**
```bash
chmod +x deploy.sh
./deploy.sh
```

2. **Configure SSL (opcional)**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d seu-dominio.com
```

## 🔧 Configuração

### Variáveis de Ambiente

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `SECRET_KEY` | Chave secreta do Flask | Gerada automaticamente |
| `JWT_SECRET_KEY` | Chave para JWT | Gerada automaticamente |
| `DATABASE_URL` | URL do banco de dados | `sqlite:///vantus.db` |
| `FLASK_ENV` | Ambiente (development/production) | `development` |

### Estrutura do Projeto

```
vantus/
├── app.py                 # Aplicação principal
├── config.py             # Configurações
├── wsgi.py              # WSGI para produção
├── requirements.txt      # Dependências Python
├── deploy.sh            # Script de deploy
├── templates/           # Templates HTML
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── change_password.html
│   ├── 404.html
│   └── 500.html
└── README.md
```

## 🔐 Funcionalidades de Segurança

### Autenticação
- Login com username/email
- Senhas criptografadas com bcrypt
- Proteção contra força bruta
- Bloqueio temporário após 5 tentativas falhadas

### Validação
- Senhas mínimas de 8 caracteres
- Verificação de força da senha
- Validação de email
- Usernames únicos

### Logs
- Logs de login/logout
- Logs de tentativas falhadas
- Logs de alteração de senha
- Logs de registro de usuários

### Headers de Segurança
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security
- Content-Security-Policy

## 📱 Interface

- **Design responsivo** com Bootstrap 5
- **Interface moderna** com gradientes e animações
- **Ícones Font Awesome** para melhor UX
- **Validação em tempo real** de senhas
- **Alertas automáticos** com auto-hide

## 🚀 Deploy

### VPS Ubuntu

1. **Conecte ao seu VPS**
```bash
ssh usuario@seu-vps.com
```

2. **Clone o projeto**
```bash
git clone https://github.com/vinieves/vantus.git
cd vantus
```

3. **Execute o deploy**
```bash
chmod +x deploy.sh
./deploy.sh
```

### Serviços Configurados

- **Nginx**: Proxy reverso
- **Gunicorn**: Servidor WSGI
- **Supervisor**: Gerenciamento de processos
- **UFW**: Firewall

### Comandos Úteis

```bash
# Ver logs
sudo tail -f /var/log/vantus/vantus.out.log

# Reiniciar aplicação
sudo supervisorctl restart vantus

# Verificar status
sudo supervisorctl status vantus

# Configurar SSL
sudo certbot --nginx -d seu-dominio.com
```

## 🔧 Manutenção

### Backup do Banco
```bash
sudo cp /var/www/vantus/vantus.db /backup/vantus_$(date +%Y%m%d).db
```

### Atualização
```bash
cd /var/www/vantus
sudo -u vantus git pull
sudo -u vantus /var/www/vantus/venv/bin/pip install -r requirements.txt
sudo supervisorctl restart vantus
```

## 📊 Monitoramento

### Logs de Segurança
- Acessos bem-sucedidos
- Tentativas falhadas
- Alterações de senha
- Registros de usuários

### Métricas
- Usuários ativos
- Tentativas de login
- Bloqueios de conta
- Atividade por IP

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 🆘 Suporte

- **Issues**: [GitHub Issues](https://github.com/vinieves/vantus/issues)
- **Documentação**: Este README
- **Email**: Entre em contato para suporte

## 🔮 Roadmap

- [ ] Autenticação de dois fatores (2FA)
- [ ] Integração com OAuth (Google, GitHub)
- [ ] API REST para integração
- [ ] Dashboard administrativo
- [ ] Notificações por email
- [ ] Backup automático
- [ ] Monitoramento avançado

---

**Desenvolvido com ❤️ para sistemas seguros** 