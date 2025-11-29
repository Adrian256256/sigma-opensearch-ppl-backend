# Sigma to OpenSearch PPL Backend

Backend pentru conversia regulilor Sigma în interogări PPL (Piped Processing Language) pentru OpenSearch.

## Descriere

Acest proiect oferă un backend pentru biblioteca pySigma care convertește regulile de detecție Sigma în interogări PPL optimizate pentru OpenSearch. PPL este un limbaj de procesare a datelor care permite interogări complexe și eficiente pe datele indexate în OpenSearch.

## Structura Proiectului

```
sigma-opensearch-ppl-backend/
├── sigma/
│   └── backends/
│       └── opensearch_ppl/
│           ├── __init__.py
│           └── opensearch_ppl.py          # Implementarea backend-ului
├── tests/
│   ├── __init__.py
│   ├── conftest.py                        # Configurație pytest și fixtures
│   ├── test_sigma_to_ppl.py              # Teste principale pentru conversie
│   ├── test_file_based.py                # Teste bazate pe fișiere YAML
│   ├── test_rules/                       # Reguli Sigma de test
│   │   ├── simple_rule.yml
│   │   ├── complex_rule.yml
│   │   ├── wildcard_rule.yml
│   │   └── numeric_comparison_rule.yml
│   └── README.md                         # Documentație pentru teste
├── pytest.ini                            # Configurație pytest
├── requirements.txt                      # Dependențe Python
└── README.md                             # Acest fișier
```

## Instalare

### Dependențe

Instalează dependențele necesare:

```bash
pip install -r requirements.txt
```

Dependențe principale:
- `pysigma` - Bibliotecă pentru procesarea regulilor Sigma
- `pytest` - Framework pentru testare
- `pyyaml` - Parsare fișiere YAML

## Teste

Proiectul include o suită completă de teste pentru verificarea conversiei corecte a regulilor Sigma în interogări PPL.

### Structura Testelor

#### 1. Teste Principale (`test_sigma_to_ppl.py`)

Teste pentru conversia de bază și cazuri complexe:

- **Teste de conversie de bază:**
  - `test_simple_rule_conversion` - Conversie reguli simple
  - `test_complex_rule_conversion` - Conversie reguli cu multiple condiții
  - `test_rule_with_keywords` - Conversie reguli cu keywords
  - `test_multiple_rules_conversion` - Conversie multiple reguli simultan

- **Teste pentru operatori și condiții:**
  - `test_condition_operators` - Testare operatori logici (AND, OR)
  - `test_wildcard_values` - Testare pattern-uri cu wildcards
  - `test_numeric_comparisons` - Testare comparații numerice (gt, lt, etc.)

- **Teste de validare:**
  - `test_ppl_query_structure` - Validare structură PPL
  - `test_ppl_syntax_validity` - Validare sintaxă PPL
  - `test_ppl_escaping` - Validare escaping caractere speciale
  - `test_field_mapping` - Verificare mapare câmpuri

- **Teste edge cases:**
  - `test_empty_collection` - Gestionare colecții goale

#### 2. Teste Bazate pe Fișiere (`test_file_based.py`)

Teste care încarcă reguli Sigma din fișiere YAML:

- `test_simple_rule_file` - Test pentru `simple_rule.yml`
- `test_complex_rule_file` - Test pentru `complex_rule.yml`
- `test_wildcard_rule_file` - Test pentru `wildcard_rule.yml`
- `test_numeric_comparison_rule_file` - Test pentru `numeric_comparison_rule.yml`
- `test_all_rules_in_directory` - Test automat pentru toate regulile

#### 3. Reguli de Test (`test_rules/`)

Directorul conține exemple de reguli Sigma pentru testare:

- **simple_rule.yml** - Regulă simplă cu o singură condiție
- **complex_rule.yml** - Regulă complexă cu multiple selecții și operatori logici
- **wildcard_rule.yml** - Regulă care testează pattern-uri cu wildcards
- **numeric_comparison_rule.yml** - Regulă cu comparații numerice

### Rulare Teste

#### Rulare toate testele:

```bash
pytest tests/
```

#### Rulare cu output detaliat:

```bash
pytest tests/ -v
```

#### Rulare un test specific:

```bash
pytest tests/test_sigma_to_ppl.py::TestSigmaToPPLConversion::test_simple_rule_conversion
```

#### Rulare teste cu coverage:

```bash
pytest tests/ --cov=sigma --cov-report=html
```

### Ce Verifică Testele

Testele verifica următoarele aspecte:

1. **Conversie corectă:** Regulile Sigma sunt convertite în interogări PPL valide
2. **Structură PPL:** Interogările generate au structură corectă pentru OpenSearch
3. **Sintaxă validă:** Interogările PPL au sintaxă corectă (paranteze echilibrate, etc.)
4. **Mapare câmpuri:** Câmpurile din regulile Sigma sunt mapate corect în PPL
5. **Operatori logici:** Operatorii AND, OR sunt convertiți corect
6. **Wildcards:** Pattern-urile cu wildcards sunt procesate corect
7. **Comparații numerice:** Operatorii de comparație (gt, lt, etc.) funcționează
8. **Edge cases:** Gestionarea corectă a cazurilor limită (colecții goale, etc.)

## Utilizare

### Exemplu de utilizare a backend-ului:

```python
from sigma.collection import SigmaCollection
from sigma.backends.opensearch_ppl.opensearch_ppl import OpenSearchPPLBackend

# Încarcă o regulă Sigma
with open('rule.yml', 'r') as f:
    sigma_collection = SigmaCollection.from_yaml(f.read())

# Creează backend-ul
backend = OpenSearchPPLBackend()

# Convertește în PPL
ppl_query = backend.convert(sigma_collection)

print(ppl_query)
```

## Dezvoltare

### Adăugare Teste Noi

Pentru a adăuga teste noi:

1. Adaugă o regulă Sigma în `tests/test_rules/` (opțional)
2. Creează un test nou în unul dintre fișierele de test
3. Folosește fixture-urile din `conftest.py` pentru backend și reguli

### Fixtures Disponibile

- `sigma_backend` - Clasa backend-ului OpenSearchPPLBackend
- `simple_sigma_rule` - Regulă Sigma simplă (dict)
- `complex_sigma_rule` - Regulă Sigma complexă (dict)
- `sigma_rule_with_keywords` - Regulă cu keywords (dict)
- `test_rules_dir` - Path către directorul cu reguli de test

## Status

- ✅ Structură proiect
- ✅ Suită completă de teste
- ✅ Reguli Sigma de exemplu
- ✅ Configurație pytest
- ⏳ Implementare backend (în dezvoltare)

## Contribuții

Pentru a contribui la acest proiect:

1. Fork repository-ul
2. Creează un branch pentru feature-ul tău
3. Adaugă teste pentru noua funcționalitate
4. Asigură-te că toate testele trec
5. Creează un pull request

## Licență

[Specifică licența aici]

## Contact

[Informații de contact]

