#!/bin/bash

# Script de deploy para VPS Ubuntu
# Sistema de Login Vantus

echo "🚀 Iniciando deploy do Vantus..."

# Atualizar sistema
echo "📦 Atualizando sistema..."
sudo apt update && sudo apt upgrade -y

# Instalar dependências
echo "🔧 Instalando dependências..."
sudo apt install -y python3 python3-pip python3-venv nginx supervisor

# Criar usuário para a aplicação
echo "👤 Criando usuário vantus..."
sudo useradd -m -s /bin/bash vantus
sudo usermod -aG sudo vantus

# Criar diretório da aplicação
echo "📁 Criando diretório da aplicação..."
sudo mkdir -p /var/www/vantus
sudo chown vantus:vantus /var/www/vantus

# Configurar ambiente virtual
echo "🐍 Configurando ambiente virtual..."
cd /var/www/vantus
sudo -u vantus python3 -m venv venv
sudo -u vantus /var/www/vantus/venv/bin/pip install --upgrade pip

# Instalar dependências Python
echo "📚 Instalando dependências Python..."
sudo -u vantus /var/www/vantus/venv/bin/pip install -r requirements.txt

# Configurar variáveis de ambiente
echo "🔐 Configurando variáveis de ambiente..."
sudo -u vantus tee /var/www/vantus/.env > /dev/null <<EOF
FLASK_ENV=production
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=sqlite:///vantus.db
EOF

# Configurar Gunicorn
echo "🦄 Configurando Gunicorn..."
sudo tee /etc/supervisor/conf.d/vantus.conf > /dev/null <<EOF
[program:vantus]
directory=/var/www/vantus
command=/var/www/vantus/venv/bin/gunicorn --workers 3 --bind unix:vantus.sock -m 007 wsgi:app
autostart=true
autorestart=true
stderr_logfile=/var/log/vantus/vantus.err.log
stdout_logfile=/var/log/vantus/vantus.out.log
user=vantus
EOF

# Criar diretório de logs
sudo mkdir -p /var/log/vantus
sudo chown vantus:vantus /var/log/vantus

# Configurar Nginx
echo "🌐 Configurando Nginx..."
sudo tee /etc/nginx/sites-available/vantus > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/vantus/vantus.sock;
    }

    location /static {
        alias /var/www/vantus/static;
    }
}
EOF

# Ativar site
sudo ln -s /etc/nginx/sites-available/vantus /etc/nginx/sites-enabled
sudo rm -f /etc/nginx/sites-enabled/default

# Configurar firewall
echo "🔥 Configurando firewall..."
sudo ufw allow 'Nginx Full'
sudo ufw allow ssh
sudo ufw --force enable

# Inicializar banco de dados
echo "🗄️ Inicializando banco de dados..."
cd /var/www/vantus
sudo -u vantus /var/www/vantus/venv/bin/python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Banco de dados inicializado com sucesso!')
"

# Reiniciar serviços
echo "🔄 Reiniciando serviços..."
sudo systemctl restart supervisor
sudo systemctl restart nginx
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start vantus

# Verificar status
echo "✅ Verificando status dos serviços..."
sudo systemctl status nginx --no-pager
sudo supervisorctl status vantus

echo "🎉 Deploy concluído!"
echo "📱 Acesse: http://$(curl -s ifconfig.me)"
echo "📋 Logs: sudo tail -f /var/log/vantus/vantus.out.log"
echo "🔧 Configuração: /var/www/vantus/.env" 