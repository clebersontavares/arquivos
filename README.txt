STW BLOCK MANAGER ANALYTICS PORTABLE V1.1.9

CORRECAO DE DESEMPENHO DOS RELATORIOS
- Dashboard e Relatorio DNS possuem cache persistente de metricas no SQLite.
- Dashboard e Relatorio Firewall possuem cache persistente de metricas no SQLite.
- Horarios padrao 00:00 e 23:59 sem datas nao criam chaves de cache diferentes.
- A lista recente de 500 eventos foi removida do calculo das metricas; a tabela usa somente a API paginada.
- Depois de importar/atualizar CSV, o Analytics prepara o cache padrao antes de retornar ATUALIZADO.
- Na inicializacao, se faltar cache padrao, ele e preparado antes de abrir o navegador.
- Filtros explicitos continuam com cache proprio apos a primeira consulta.

BANCO
- Windows: %LOCALAPPDATA%\STW\BlockManagerAnalytics\blockmanager-analytics.db
- Cache: tabela analytics_cache no mesmo SQLite.
- Mesmo CSV: JA ATUALIZADO.
- Mesmo nome alterado: substitui os eventos do arquivo sem duplicar.

GRANDES VOLUMES
- Visualizacao completa acima de 10.000 registros mostra relatorio gerencial e amostra de 500.
- Tela de eventos usa paginacao SQL.
- CSV continua contendo todas as entradas filtradas.
