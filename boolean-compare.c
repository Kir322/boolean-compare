#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <stdarg.h>
#include <math.h>
#include <stdlib.h>

typedef struct BufHdr {
    size_t cap;
    size_t len;
    char buf[];
} BufHdr;

#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define buf__hdr(b) ((BufHdr *)((char *)(b) - 2*sizeof(size_t)))
#define buf__fits(b, n) (buf_len(b) + n <= buf_cap(b))
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = buf__grow((b), buf_len(b) + (n), sizeof(*(b)))))

#define buf_cap(b) ((b) ? buf__hdr(b)->cap : 0)
#define buf_len(b) ((b) ? buf__hdr(b)->len : 0)
#define buf_push(b, ...) (buf__fit(b, 1), (b)[buf_len(b)] = (__VA_ARGS__), buf__hdr(b)->len++)
#define buf_pop(b) (buf_len(b) > 0 ? (buf__hdr(b)->len--, (b)[buf_len(b)]) : 0)
#define buf_free(b) ((b) ? (free(buf__hdr(b)), (b) = 0) : 0)
#define buf_clear(b) ((b) ? buf__hdr(b)->len = 0 : 0)

void *buf__grow(void *data, size_t new_len, size_t elem_size) {
    size_t new_cap = MAX(1 + 2*buf_cap(data), new_len);
    assert(new_cap >= new_len);
    size_t new_size = new_cap * elem_size + 2*sizeof(size_t); // offsetof(BufHdr, buf);
    BufHdr *new_hdr;
    if (data) {
        new_hdr = (BufHdr *)realloc(buf__hdr(data) /* offsetof(BufHdr, buf) */, new_size);
    } else {
        new_hdr = (BufHdr *)malloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf;
}

/*
expr     := or-expr (',' or-expr)*
or-expr  := xor-expr ('|' or-expr)*
xor-expr := and-expr ('^' xor-expr)*
and-expr := not-expr ('&' and-expr)*
not-expr := '~' not-expr
          | '(' or-expr ')'
          | IDENTIFIER
          | LITERAL
 */

char *input_stream;

typedef enum TokenKind {
    TOKEN_IDENTIFIER,
    TOKEN_LITERAL,
    TOKEN_OR,
    TOKEN_AND,
    TOKEN_NOT,
    TOKEN_LEFT_PAREN,
    TOKEN_RIGHT_PAREN,
    TOKEN_XOR,
    TOKEN_SEPARATOR
} TokenKind;

typedef struct Token {
    TokenKind kind;
    union {
        int value;
        char name;
    };
} Token;

Token current_token;

char *token_type_names[] = {
    [TOKEN_IDENTIFIER] = &current_token.name,
    // [TOKEN_LITERAL] = (current_token.value + '0'),
    [TOKEN_OR] = "|",
    [TOKEN_AND] = "&",
    [TOKEN_NOT] = "~",
    [TOKEN_LEFT_PAREN] = "(",
    [TOKEN_RIGHT_PAREN] = ")",
    [TOKEN_XOR] = "^",
    [TOKEN_SEPARATOR] = ","
};

void error(char*, ...);

void next_token() {
    while (isspace(*input_stream)) {
        input_stream++;
    }

    char c = *input_stream++;
    switch (c) {
        case 'A': case 'B': case 'C': case 'D':
        case 'E': case 'F': case 'G': case 'H':
        case 'I': case 'J': case 'K': case 'L':
        case 'M': case 'N': case 'O': case 'P':
        case 'Q': case 'R': case 'S': case 'T':
        case 'U': case 'V': case 'W': case 'X':
        case 'Y': case 'Z':
            current_token.kind = TOKEN_IDENTIFIER;
            current_token.name = c;
            break;
        case '~':
            current_token.kind = TOKEN_NOT;
            break;
        case '&':
            current_token.kind = TOKEN_AND;
            break;
        case '|':
            current_token.kind = TOKEN_OR;
            break;
        case '(':
            current_token.kind = TOKEN_LEFT_PAREN;
            break;
        case ')':
            current_token.kind = TOKEN_RIGHT_PAREN;
            break;
        case '^':
            current_token.kind = TOKEN_XOR;
            break;
        case ',':
            current_token.kind = TOKEN_SEPARATOR;
            break;
        case '0': case '1':
            current_token.kind = TOKEN_LITERAL;
            current_token.value = c - '0';
            break;
        case 0:
            break;
        default:
            error("Unexpected token '%c'\n", c);
            break;
    }
}

void error(char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void expect_token(TokenKind expected) {
    if (current_token.kind == expected) {
        next_token();
        return;
    }

    error("Expected token '%s' got '%s'\n", token_type_names[expected], token_type_names[current_token.kind]);
}

typedef struct Expr Expr;

Expr *expr_name(char);
Expr *expr_literal(int);
Expr *expr_unary(TokenKind, Expr *);
Expr *expr_binary(TokenKind, Expr *, Expr *);
Expr *expr_group(Expr *);

Expr *parse_or_expr();

Expr *parse_not_expr() {
    Expr *expr;
    if (current_token.kind == TOKEN_NOT) {
        TokenKind op = current_token.kind;
        next_token();
        Expr *right = parse_not_expr();
        expr =  expr_unary(op, right);
    } else if (current_token.kind == TOKEN_LEFT_PAREN) {
        next_token();
        Expr *e = parse_or_expr();
        expr = expr_group(e);
        expect_token(TOKEN_RIGHT_PAREN);
    } else if (current_token.kind == TOKEN_IDENTIFIER) {
        expr = expr_name(current_token.name);
        next_token();
    } else if (current_token.kind == TOKEN_LITERAL) {
        expr = expr_literal(current_token.value);
        next_token();
    }

    return expr;
}

Expr *parse_and_expr() {
    Expr *expr = parse_not_expr();

    while (current_token.kind == TOKEN_AND) {
        TokenKind op = current_token.kind;
        next_token();
        Expr *right = parse_and_expr();
        expr = expr_binary(op, expr, right);
    }

    return expr;
}

Expr *parse_xor_expr() {
    Expr *expr = parse_and_expr();

    while (current_token.kind == TOKEN_XOR) {
        TokenKind op = current_token.kind;
        next_token();
        Expr *right = parse_xor_expr();
        expr = expr_binary(op, expr, right);
    } 

    return expr;
}

Expr *parse_or_expr() {
    Expr *expr = parse_xor_expr();

    while (current_token.kind == TOKEN_OR) {
        TokenKind op = current_token.kind;
        next_token();
        Expr *right = parse_or_expr();
        expr = expr_binary(op, expr, right);
    }

    return expr;
}

Expr **parse_exprs() {
    next_token();
    Expr **expr_buf = 0;
    Expr *expr = parse_or_expr();
    buf_push(expr_buf, expr);

    while (current_token.kind == TOKEN_SEPARATOR) {
        next_token();
        Expr *next = parse_or_expr();
        buf_push(expr_buf, next);
    }

    return expr_buf;
}

typedef enum ExprKind {
    EXPR_UNARY,
    EXPR_BINARY,
    EXPR_NAME,
    EXPR_LITERAL,
    EXPR_GROUP
} ExprKind;

typedef struct Expr {
    ExprKind kind;
    union {
        char name;
        int literal;
        struct {
            TokenKind op;
            Expr *left, *right;
        } binary;

        struct {
            TokenKind op;
            Expr *right;
        } unary;

        Expr *group;
    };
} Expr;

Expr *expr_alloc(ExprKind kind) {
    Expr *expr = (Expr*)malloc(sizeof(Expr));
    expr->kind = kind;
    return expr;
}

Expr *expr_name(char name) {
    Expr *expr = expr_alloc(EXPR_NAME);
    expr->name = name;
    return expr;
}

Expr *expr_literal(int value) {
    Expr *expr = expr_alloc(EXPR_LITERAL);
    expr->literal = value;
    return expr;
}

Expr *expr_unary(TokenKind op, Expr *right) {
    Expr *expr = expr_alloc(EXPR_UNARY);
    expr->unary.right = right;
    expr->unary.op = op;
    return expr;
}

Expr *expr_binary(TokenKind op, Expr *left, Expr *right) {
    Expr *expr = expr_alloc(EXPR_BINARY);
    expr->binary.left = left;
    expr->binary.right = right;
    expr->binary.op = op;
    return expr;
}

Expr *expr_group(Expr *e) {
    Expr *expr = expr_alloc(EXPR_GROUP);
    expr->group = e;
    return expr;
}

int get_arg_state(char arg, int state, char *args) {
    int location = -1;
    for (int i = 0; i < buf_len(args); ++i) {
        if (args[i] == arg) {
            location = i;
            break;
        }
    }
    if (location == -1) error("Undefined variable '%c'\n", arg);
    return (state >> location) & 1;
}

void print_ast(Expr *expr, int state, char *args) {
    switch (expr->kind) {
        case EXPR_NAME:
            printf("%c(%d)", expr->name, get_arg_state(expr->name, state, args));
            break;
        case EXPR_GROUP:
            printf("(");
            print_ast(expr->group, state, args);
            printf(")");
            break;
        case EXPR_UNARY:
            printf("%s", token_type_names[expr->unary.op]);
            print_ast(expr->unary.right, state, args);
            break;
        case EXPR_BINARY:
            print_ast(expr->binary.left, state, args);
            printf(" %s ", token_type_names[expr->binary.op]);
            print_ast(expr->binary.right, state, args);
            break;
        case EXPR_LITERAL:
            printf("%d ", expr->literal);
            break;
    }
}

int eval_expr(Expr *expr, int state, char *args) {
    switch (expr->kind) {
        case EXPR_UNARY: {
            int right = eval_expr(expr->unary.right, state, args);
            switch (expr->unary.op) {
                case TOKEN_NOT:
                    return right ^ 1;
            }
        }
        case EXPR_BINARY: {
            int left = eval_expr(expr->binary.left, state, args);
            switch (expr->binary.op) {
                case TOKEN_AND:
                    if (!left) {
                        return 0;
                    } else {
                        return left & eval_expr(expr->binary.right, state, args);
                    }
                case TOKEN_OR:
                    if (left) {
                        return 1;
                    } else {
                        return left | eval_expr(expr->binary.right, state, args);
                    }
                case TOKEN_XOR:
                    return left ^ eval_expr(expr->binary.right, state, args);
            }
        }
        case EXPR_GROUP:
            return eval_expr(expr->group, state, args);
        case EXPR_LITERAL:
            return expr->literal;
        case EXPR_NAME:
            return get_arg_state(expr->name, state, args);
    }
}

typedef struct BoolFunc {
    Expr *expr;
    char *args;
    size_t num_args;
} BoolFunc;

void init_args(BoolFunc *func) {
    Expr **expr_stack = 0;
    buf_push(expr_stack, func->expr);
    while (buf_len(expr_stack) > 0) {
        Expr *expr = buf_pop(expr_stack);
        if (expr->kind == EXPR_UNARY) {
            buf_push(expr_stack, expr->unary.right);
        } else if (expr->kind == EXPR_BINARY) {
            buf_push(expr_stack, expr->binary.right);
            buf_push(expr_stack, expr->binary.left);
        } else if (expr->kind == EXPR_NAME) {
            for (int i = 0; i < buf_len(func->args); ++i) {
                if (func->args[i] == expr->name) goto end_name;
            }
            buf_push(func->args, expr->name);
            func->num_args++;
            end_name: continue;
        } else if (expr->kind == EXPR_GROUP) {
            buf_push(expr_stack, expr->group);
        }
    }
    buf_free(expr_stack);
}

BoolFunc *bool_funcs(Expr **exprs) {
    BoolFunc *funcs = 0;
    for (int i = 0; i < buf_len(exprs); ++i) {
        BoolFunc func = (BoolFunc){.expr = exprs[i]};
        init_args(&func);
        buf_push(funcs, func);
    }
    return funcs;
}

int eval_func(BoolFunc func, int state) {
    return eval_expr(func.expr, state, func.args);
}

void print_func(BoolFunc func, int state) {
    print_ast(func.expr, state, func.args);
}

void buf_test() {
    enum {
        N = 256
    };
    int* buf = 0;
    for (int i = 0; i < N; ++i) {
        buf_push(buf, i);
    }
    assert(buf_len(buf) == N);
    for (int i = 0; i < buf_len(buf); ++i) {
        assert(buf[i] == i);
    }
    for (int i = N - 1; i >= 0; --i) {
        int val = buf_pop(buf);
        assert(val == i);
    }
    assert(buf_len(buf) == 0);
    assert(buf_cap(buf) != 0);
    buf_free(buf);
    assert(buf == 0);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        error("Usage: boolean-compare <boolean function>\n");
    }
    
    input_stream = argv[1];

    Expr **exprs = parse_exprs();
    BoolFunc *funcs = bool_funcs(exprs);
    
    for (int i = 0; i < buf_len(funcs); ++i) {
        for (int state = 0; state < (int)pow(2, funcs[i].num_args); ++state) {
            print_func(funcs[i], state);
            printf(" = %d\n", eval_func(funcs[i], state));
        }
        printf("\n");
    }

    // buf_test();

    return 0;
}