/**
 * Calico selector expression parser and evaluator.
 *
 * DISCLAIMER: This is a best-effort emulation of Calico's selector language
 * for educational and visualization purposes. It is NOT the actual Calico
 * selector engine and may differ in edge cases. Do not use this to make
 * production security decisions — always verify against a real Calico cluster.
 *
 * Supported syntax:
 *   all()                          — matches everything
 *   global()                       — matches host endpoints (not namespace-scoped)
 *   has(label)                     — label exists
 *   !has(label)                    — label does not exist
 *   label == 'value'               — exact equality
 *   label != 'value'               — inequality
 *   label in { 'a', 'b' }         — value is one of the set
 *   label not in { 'a', 'b' }     — value is not in the set
 *   label starts with 'prefix'    — prefix match
 *   label ends with 'suffix'      — suffix match
 *   expr && expr                   — logical AND
 *   expr || expr                   — logical OR
 *   !expr                          — logical NOT
 *   (expr)                         — grouping
 */

// ---- AST Node Types ----

interface AllNode { kind: 'all' }
interface GlobalNode { kind: 'global' }
interface HasNode { kind: 'has'; label: string }
interface EqNode { kind: 'eq'; label: string; value: string }
interface NeqNode { kind: 'neq'; label: string; value: string }
interface InNode { kind: 'in'; label: string; values: string[] }
interface NotInNode { kind: 'notIn'; label: string; values: string[] }
interface StartsWithNode { kind: 'startsWith'; label: string; value: string }
interface EndsWithNode { kind: 'endsWith'; label: string; value: string }
interface AndNode { kind: 'and'; left: SelectorNode; right: SelectorNode }
interface OrNode { kind: 'or'; left: SelectorNode; right: SelectorNode }
interface NotNode { kind: 'not'; operand: SelectorNode }

export type SelectorNode =
  | AllNode | GlobalNode | HasNode
  | EqNode | NeqNode | InNode | NotInNode
  | StartsWithNode | EndsWithNode
  | AndNode | OrNode | NotNode;

// ---- Tokenizer ----

type TokenType =
  | 'IDENT' | 'STRING' | 'LPAREN' | 'RPAREN'
  | 'LBRACE' | 'RBRACE' | 'COMMA'
  | 'EQ' | 'NEQ' | 'AND' | 'OR' | 'NOT'
  | 'IN' | 'HAS' | 'ALL' | 'GLOBAL'
  | 'STARTS' | 'WITH' | 'ENDS'
  | 'EOF';

interface Token {
  type: TokenType;
  value: string;
  pos: number;
}

const KEYWORDS: Record<string, TokenType> = {
  'all': 'ALL',
  'global': 'GLOBAL',
  'has': 'HAS',
  'in': 'IN',
  'not': 'NOT',
  'starts': 'STARTS',
  'ends': 'ENDS',
  'with': 'WITH',
};

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < input.length) {
    // Skip whitespace
    if (/\s/.test(input[i])) { i++; continue; }

    const pos = i;

    // Two-character operators
    if (input[i] === '=' && input[i + 1] === '=') {
      tokens.push({ type: 'EQ', value: '==', pos }); i += 2; continue;
    }
    if (input[i] === '!' && input[i + 1] === '=') {
      tokens.push({ type: 'NEQ', value: '!=', pos }); i += 2; continue;
    }
    if (input[i] === '&' && input[i + 1] === '&') {
      tokens.push({ type: 'AND', value: '&&', pos }); i += 2; continue;
    }
    if (input[i] === '|' && input[i + 1] === '|') {
      tokens.push({ type: 'OR', value: '||', pos }); i += 2; continue;
    }

    // Single-character tokens
    if (input[i] === '(') { tokens.push({ type: 'LPAREN', value: '(', pos }); i++; continue; }
    if (input[i] === ')') { tokens.push({ type: 'RPAREN', value: ')', pos }); i++; continue; }
    if (input[i] === '{') { tokens.push({ type: 'LBRACE', value: '{', pos }); i++; continue; }
    if (input[i] === '}') { tokens.push({ type: 'RBRACE', value: '}', pos }); i++; continue; }
    if (input[i] === ',') { tokens.push({ type: 'COMMA', value: ',', pos }); i++; continue; }
    if (input[i] === '!') { tokens.push({ type: 'NOT', value: '!', pos }); i++; continue; }

    // Quoted string (single or double quotes)
    if (input[i] === "'" || input[i] === '"') {
      const quote = input[i];
      i++;
      let str = '';
      while (i < input.length && input[i] !== quote) {
        if (input[i] === '\\' && i + 1 < input.length) {
          str += input[i + 1]; i += 2;
        } else {
          str += input[i]; i++;
        }
      }
      if (i < input.length) i++; // skip closing quote
      tokens.push({ type: 'STRING', value: str, pos });
      continue;
    }

    // Identifiers and keywords
    // Calico label keys can contain: letters, digits, -, _, ., /
    if (/[a-zA-Z0-9_\-./]/.test(input[i])) {
      let ident = '';
      while (i < input.length && /[a-zA-Z0-9_\-./]/.test(input[i])) {
        ident += input[i]; i++;
      }
      const kw = KEYWORDS[ident.toLowerCase()];
      if (kw) {
        tokens.push({ type: kw, value: ident, pos });
      } else {
        tokens.push({ type: 'IDENT', value: ident, pos });
      }
      continue;
    }

    throw new Error(`Unexpected character '${input[i]}' at position ${i}`);
  }

  tokens.push({ type: 'EOF', value: '', pos: i });
  return tokens;
}

// ---- Parser (recursive descent, precedence: || < && < ! < primary) ----

class Parser {
  private tokens: Token[];
  private pos = 0;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token {
    return this.tokens[this.pos];
  }

  private advance(): Token {
    const t = this.tokens[this.pos];
    this.pos++;
    return t;
  }

  private expect(type: TokenType): Token {
    const t = this.peek();
    if (t.type !== type) {
      throw new Error(`Expected ${type} but got ${t.type} ('${t.value}') at position ${t.pos}`);
    }
    return this.advance();
  }

  parse(): SelectorNode {
    const node = this.parseOr();
    if (this.peek().type !== 'EOF') {
      const t = this.peek();
      throw new Error(`Unexpected token '${t.value}' at position ${t.pos}`);
    }
    return node;
  }

  private parseOr(): SelectorNode {
    let left = this.parseAnd();
    while (this.peek().type === 'OR') {
      this.advance();
      const right = this.parseAnd();
      left = { kind: 'or', left, right };
    }
    return left;
  }

  private parseAnd(): SelectorNode {
    let left = this.parseUnary();
    while (this.peek().type === 'AND') {
      this.advance();
      const right = this.parseUnary();
      left = { kind: 'and', left, right };
    }
    return left;
  }

  private parseUnary(): SelectorNode {
    if (this.peek().type === 'NOT') {
      this.advance();
      const operand = this.parseUnary();
      return { kind: 'not', operand };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): SelectorNode {
    const t = this.peek();

    // all()
    if (t.type === 'ALL') {
      this.advance();
      this.expect('LPAREN');
      this.expect('RPAREN');
      return { kind: 'all' };
    }

    // global()
    if (t.type === 'GLOBAL') {
      this.advance();
      this.expect('LPAREN');
      this.expect('RPAREN');
      return { kind: 'global' };
    }

    // has(label)
    if (t.type === 'HAS') {
      this.advance();
      this.expect('LPAREN');
      const label = this.parseLabel();
      this.expect('RPAREN');
      return { kind: 'has', label };
    }

    // Grouped expression: ( expr )
    if (t.type === 'LPAREN') {
      this.advance();
      const expr = this.parseOr();
      this.expect('RPAREN');
      return expr;
    }

    // Label-based expressions: label == 'val', label != 'val',
    // label in { ... }, label not in { ... },
    // label starts with 'val', label ends with 'val'
    if (t.type === 'IDENT') {
      const label = this.parseLabel();
      const op = this.peek();

      if (op.type === 'EQ') {
        this.advance();
        const value = this.parseStringValue();
        return { kind: 'eq', label, value };
      }

      if (op.type === 'NEQ') {
        this.advance();
        const value = this.parseStringValue();
        return { kind: 'neq', label, value };
      }

      if (op.type === 'IN') {
        this.advance();
        const values = this.parseSet();
        return { kind: 'in', label, values };
      }

      if (op.type === 'NOT') {
        // "not in { ... }"
        this.advance();
        this.expect('IN');
        const values = this.parseSet();
        return { kind: 'notIn', label, values };
      }

      if (op.type === 'STARTS') {
        this.advance();
        this.expect('WITH');
        const value = this.parseStringValue();
        return { kind: 'startsWith', label, value };
      }

      if (op.type === 'ENDS') {
        this.advance();
        this.expect('WITH');
        const value = this.parseStringValue();
        return { kind: 'endsWith', label, value };
      }

      throw new Error(`Unexpected operator '${op.value}' after label '${label}' at position ${op.pos}`);
    }

    throw new Error(`Unexpected token '${t.value}' at position ${t.pos}`);
  }

  /**
   * Parse a label key. Since Calico label keys can include characters like '/'
   * and '.', the tokenizer may split them across multiple IDENT tokens or even
   * keyword tokens (e.g. "projectcalico.org/name" → "projectcalico", ".", "org", "/", "name").
   * But our tokenizer handles that as a single IDENT because /[a-zA-Z0-9_\-./]/ is the
   * character class. If the label is a keyword like "not" used as label name,
   * we accept keyword tokens as labels too.
   */
  private parseLabel(): string {
    const t = this.peek();
    if (t.type === 'IDENT' || t.type === 'STRING') {
      return this.advance().value;
    }
    // Accept keywords as label names (rare but valid)
    if (t.type === 'HAS' || t.type === 'ALL' || t.type === 'GLOBAL' ||
        t.type === 'IN' || t.type === 'NOT' || t.type === 'STARTS' ||
        t.type === 'ENDS' || t.type === 'WITH') {
      return this.advance().value;
    }
    throw new Error(`Expected label name but got '${t.value}' at position ${t.pos}`);
  }

  private parseStringValue(): string {
    const t = this.peek();
    if (t.type === 'STRING') return this.advance().value;
    // Allow unquoted identifiers as values for convenience
    if (t.type === 'IDENT') return this.advance().value;
    throw new Error(`Expected string value but got '${t.value}' at position ${t.pos}`);
  }

  private parseSet(): string[] {
    this.expect('LBRACE');
    const values: string[] = [];
    if (this.peek().type !== 'RBRACE') {
      values.push(this.parseStringValue());
      while (this.peek().type === 'COMMA') {
        this.advance();
        // Allow trailing comma
        if (this.peek().type === 'RBRACE') break;
        values.push(this.parseStringValue());
      }
    }
    this.expect('RBRACE');
    return values;
  }
}

// ---- Public API ----

/**
 * Parse a Calico selector expression string into an AST.
 * Throws on syntax errors.
 */
export function parseSelectorExpression(input: string): SelectorNode {
  const trimmed = input.trim();
  if (trimmed === '' || trimmed === 'all()') {
    return { kind: 'all' };
  }
  const tokens = tokenize(trimmed);
  const parser = new Parser(tokens);
  return parser.parse();
}

/**
 * Evaluate a Calico selector expression against a set of labels.
 *
 * Returns true if the labels satisfy the selector.
 * Throws on syntax errors in the selector.
 *
 * Note: `global()` always returns false when evaluated against pod labels,
 * since it targets host endpoints which are not modeled here.
 */
export function evaluateSelector(selector: string, labels: Record<string, string>): boolean {
  const ast = parseSelectorExpression(selector);
  return evalNode(ast, labels);
}

function evalNode(node: SelectorNode, labels: Record<string, string>): boolean {
  switch (node.kind) {
    case 'all':
      return true;
    case 'global':
      // global() matches host endpoints — we're testing pod/workload labels
      return false;
    case 'has':
      return node.label in labels;
    case 'eq':
      return labels[node.label] === node.value;
    case 'neq':
      return node.label in labels && labels[node.label] !== node.value;
    case 'in':
      return node.label in labels && node.values.includes(labels[node.label]);
    case 'notIn':
      return !(node.label in labels) || !node.values.includes(labels[node.label]);
    case 'startsWith':
      return node.label in labels && labels[node.label].startsWith(node.value);
    case 'endsWith':
      return node.label in labels && labels[node.label].endsWith(node.value);
    case 'and':
      return evalNode(node.left, labels) && evalNode(node.right, labels);
    case 'or':
      return evalNode(node.left, labels) || evalNode(node.right, labels);
    case 'not':
      return !evalNode(node.operand, labels);
  }
}
