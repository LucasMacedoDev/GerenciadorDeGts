# Gerenciador de GTs Ilan — versão multiusuário

## Preparação
1. Faça backup do projeto e do banco de dados original antes de atualizar. Para aproveitar os volumes antigos, atualize **na pasta do projeto original**, preservando o nome do projeto Compose. Não execute `docker compose down -v`.
2. Copie `.env.example` para `.env` e gere `SESSION_SECRET` com `openssl rand -hex 32`.
3. Configure SMTP_HOST, SMTP_USER e SMTP_PASSWORD (senha de aplicativo do provedor), além de PUBLIC_URL. Sem SMTP configurado, o cadastro devolve 503; a aplicação **não simula envio de emails**.
4. Execute `docker compose up --build -d`, depois `docker compose logs -f backend`.
5. Abra http://localhost:5173, clique em solicitar cadastro, informe `contato.lucasmacedodev@gmail.com` e uma senha de no mínimo 12 caracteres. O endereço só vira administrador após a confirmação real por link enviado ao email. Os demais se cadastram como líderes, confirmam email e aguardam aprovação do admin.
6. Faça login como admin e clique em **Aprovações / líderes** para aprovar ou revogar acesso.

## Limites e implantação pública
- As reuniões e pessoas novas pertencem ao usuário autenticado e não aparecem em painéis de outros líderes.
- Registros da versão anterior sem proprietário ficam preservados no banco, mas não aparecem automaticamente nos painéis. É necessária uma migração supervisionada para atribuir o acervo legado ao administrador, após backup.
- Exclusão de histórico é uma operação exclusiva de admin na API `DELETE /api/admin/meetings/{id}`; a interface de exclusão ainda não está disponível.
- Para colocar na internet, use domínio, HTTPS, proxy reverso, `COOKIE_SECURE=true`, SMTP operacional, backups, controle de acesso aos backups e política de consentimento/retenção de dados biométricos. Não exponha portas de desenvolvimento do Vite nem FastAPI diretamente na internet.
- Esta versão ainda não inclui recuperação de senha, limitação de tentativas, proteção CSRF dedicada ou trilha completa de auditoria. **Não usar em produção pública sem esses reforços e revisão de segurança.**
- O reconhecimento facial real permanece dependente do DeepFace e de seus modelos; não há resultados simulados.
