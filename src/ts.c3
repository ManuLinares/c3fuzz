module ts;
// Minimal Tree-Sitter bindings for C3
// Internal header: dep/tree-sitter-c3/src/tree_sitter/parser.h

typedef TSParser = void;
typedef TSTree = void;
typedef TSLanguage = void;

struct TSPoint
{
	uint row;
	uint column;
}

struct TSRange
{
	TSPoint start_point;
	TSPoint end_point;
	uint start_byte;
	uint end_byte;
}

struct TSNode
{
	uint[4] context;
	void* id;
	TSTree* tree;
}

extern fn TSParser* ts_parser_new();
extern fn void ts_parser_delete(TSParser* parser);
extern fn bool ts_parser_set_language(TSParser* parser, TSLanguage* language);
extern fn void ts_parser_reset(TSParser* parser);
extern fn TSTree* ts_parser_parse_string(TSParser* parser, TSTree* old_tree, ZString string, uint length);
extern fn void ts_tree_delete(TSTree* tree);
extern fn TSNode ts_tree_root_node(TSTree* tree);

extern fn ZString ts_node_type(TSNode node);
extern fn uint ts_node_child_count(TSNode node);
extern fn TSNode ts_node_child(TSNode node, uint child_index);
extern fn uint ts_node_start_byte(TSNode node);
extern fn uint ts_node_end_byte(TSNode node);
extern fn bool ts_node_is_named(TSNode node);
extern fn bool ts_node_has_error(TSNode node);
extern fn ushort ts_node_symbol(TSNode node);

extern fn TSLanguage* tree_sitter_c3();
