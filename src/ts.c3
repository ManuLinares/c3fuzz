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

extern fn TSParser* ts_parser_new() @cname("ts_parser_new");
extern fn void ts_parser_delete(TSParser* parser) @cname("ts_parser_delete");
extern fn bool ts_parser_set_language(TSParser* parser, TSLanguage* language) @cname("ts_parser_set_language");
extern fn void ts_parser_reset(TSParser* parser) @cname("ts_parser_reset");
extern fn TSTree* ts_parser_parse_string(TSParser* parser, TSTree* old_tree, ZString string, uint length) @cname("ts_parser_parse_string");
extern fn void ts_tree_delete(TSTree* tree) @cname("ts_tree_delete");
extern fn TSNode ts_tree_root_node(TSTree* tree) @cname("ts_tree_root_node");

extern fn ZString ts_node_type(TSNode node) @cname("ts_node_type");
extern fn uint ts_node_child_count(TSNode node) @cname("ts_node_child_count");
extern fn TSNode ts_node_child(TSNode node, uint child_index) @cname("ts_node_child");
extern fn uint ts_node_start_byte(TSNode node) @cname("ts_node_start_byte");
extern fn uint ts_node_end_byte(TSNode node) @cname("ts_node_end_byte");
extern fn bool ts_node_is_named(TSNode node) @cname("ts_node_is_named");
extern fn bool ts_node_has_error(TSNode node) @cname("ts_node_has_error");
extern fn ushort ts_node_symbol(TSNode node) @cname("ts_node_symbol");

extern fn TSLanguage* tree_sitter_c3() @cname("tree_sitter_c3");
