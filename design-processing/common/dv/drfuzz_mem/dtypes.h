#ifndef DTYPE_H
#define DTYPE_H

#include "macros.h"
#include "dtypes.h"
#include "instructions.h"

class Testbench; // forward declaration to break cyclic dependencies in headers

enum tick_req_type_e {
	REQ_NONE,
	REQ_STOP,
	REQ_INTREGDUMP,
	REQ_FLOATREGDUMP,
	REQ_REGSTREAM
};


typedef struct {
	enum tick_req_type_e type;
	uint64_t content;
	uint64_t content_t0;
	uint32_t id;
	void print();
	std::string get_json();
} tick_req_t;

typedef struct {
	uint32_t val;
	uint32_t taint;
} taint_inject_t;

struct doutput_t {
	public:
		uint32_t coverage[N_COV_POINTS_b32];
		uint32_t taints[N_TAINT_OUTPUTS_b32];
		uint32_t asserts[N_ASSERTS_b32];

		void dump(Testbench *tb);
		void dump_q(Testbench *tb);
		std::string get_cov_str();
		void print();
		bool failed();
		void check_failed();
		void check();
		void print_diff(doutput_t *other);
		void print_asserts_diff(doutput_t *other);
		void print_increase(doutput_t *other);
		void add_or(doutput_t *other);
		void init();
		void print_hex_mask();
		size_t get_muxcount();
		std::string get_str();

		#ifdef TAINT_EN
		std::string get_cov_t0_str();
		void print_taint_map();
		void print_taint_diff(doutput_t *other);
		bool compare_taints(doutput_t *other);
		bool is_tainted();
		size_t get_taintcount();
		size_t get_untoggled_taintcount();
		size_t get_n_untoggled_by_this_and_tainted_by_other(doutput_t *other);
		#endif
};
#endif //DTYPE_H
