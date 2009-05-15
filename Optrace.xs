#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#define NEED_pv_pretty
#define NEED_pv_escape
#define NEED_my_snprintf
#include "ppport.h"

#ifndef SvRXOK
#define SvRXOK(sv) (SvROK(sv) && mg_find(SvRV(sv), PERL_MAGIC_qr))
#endif

#ifndef gv_stashpvs
#define gv_stashpvs(s, create) Perl_gv_stashpvn(aTHX_ STR_WITH_LEN(s), create)
#endif

#ifndef CopLABEL
#define CopLABEL(cop) ((cop)->cop_label)
#endif

#define PACKAGE "Devel::Optrace"

#define MY_CXT_KEY PACKAGE "::_guts" XS_VERSION
typedef struct{
	SV* debugsv;

	HV* debsv_seen;
	SV* debf_buff;
	SV* buff;

	PerlIO* log;

	runops_proc_t orig_runops;
	peep_t        orig_peepp;
} my_cxt_t;
START_MY_CXT

#define dMY_DEBUG dMY_CXT; register U32 const debug = (U32)SvUV(MY_CXT.debugsv)

#define DOf_TRACE   0x01
#define DOf_STACK   0x02
#define DOf_RUNOPS  0x04
#define DOf_NOOPT   0x08
#define DOf_ALL     (DOf_TRACE | DOf_STACK | DOf_RUNOPS)

#define DO_TRACE   (debug & DOf_TRACE)
#define DO_STACK   (debug & DOf_STACK)
#define DO_RUNOPS  (debug & DOf_RUNOPS)
#define DO_NOOPT   (debug & DOf_NOOPT)

#define PV_LIMIT (50)

#define debs(s)         do_debpvn(aTHX_ aMY_CXT_ STR_WITH_LEN(s))
#define debpvn(pv, len) do_debpvn(aTHX_ aMY_CXT_ pv, len)
static void
do_debpvn(pTHX_ pMY_CXT_ const char* pv, STRLEN const len){
	dVAR;
	PerlIO_write(MY_CXT.log, pv, len);
}

#define debpv(pv) do_debpv(aTHX_ aMY_CXT_ pv)
static void
do_debpv(pTHX_ pMY_CXT_ const char* const pv){
	dVAR;
	debpvn(pv, strlen(pv));
}

#define debsv_simple(sv) do_debsv_simple(aTHX_ aMY_CXT_ sv)
static void
do_debsv_simple(pTHX_ pMY_CXT_ SV* const sv){
	dVAR;
	STRLEN len;
	const char* const pv = SvPV_const(sv, len);
	debpvn(pv, len);
}


#define debf do_debf_nocontext
static void
do_debf_nocontext(const char* const fmt, ...){
	dTHX;
	dMY_CXT;
	va_list args;

	va_start(args, fmt);
	sv_vsetpvf(MY_CXT.debf_buff, fmt, &args);
	va_end(args);

	debsv_simple(MY_CXT.debf_buff);
}


#define debgv(gv, prefix) do_debgv(aTHX_ aMY_CXT_ gv, prefix)
static void
do_debgv(pTHX_ pMY_CXT_ GV* const gv, const char* const prefix){
	SV* const dsv = MY_CXT.buff;
	const char* pv;
	I32 i, len;
	gv_efullname4(dsv, gv, prefix, FALSE);

	pv  = SvPVX(dsv);
	len = SvCUR(dsv);
	for(i = 0; i < len; i++){
		if(isCNTRL(pv[i])){
			char ctrl[2];
			ctrl[0] = '^';
			ctrl[1] = toCTRL(pv[i]);

			sv_insert(dsv, i, 1, ctrl, 2);

			pv  = SvPVX(dsv);
			len = SvCUR(dsv);
		}
	}
	debpvn(pv, len);
}

static const char*
do_magic_name(const char mgtype){
	/* stolen from dump.c */
	static const struct { const char type; const char *name; } magic_names[] = {
		{ PERL_MAGIC_sv,             "sv" },
		{ PERL_MAGIC_arylen,         "arylen" },
		{ PERL_MAGIC_glob,           "glob" },
#ifdef PERL_MAGIC_rhash
		{ PERL_MAGIC_rhash,          "rhash" },
#endif
		{ PERL_MAGIC_pos,            "pos" },
#ifdef PERL_MAGIC_symtab
		{ PERL_MAGIC_symtab,         "symtab" },
#endif
		{ PERL_MAGIC_backref,        "backref" },
#ifdef PERL_MAGIC_arylen_p
		{ PERL_MAGIC_arylen_p,       "arylen_p" },
#endif
#ifdef PERL_MAGIC_arylen
		{ PERL_MAGIC_arylen,         "arylen" },
#endif
		{ PERL_MAGIC_overload,       "overload" },
		{ PERL_MAGIC_bm,             "bm" },
		{ PERL_MAGIC_regdata,        "regdata" },
		{ PERL_MAGIC_env,            "env" },
#ifdef PERL_MAGIC_hints
		{ PERL_MAGIC_hints,          "hints" },
#endif
		{ PERL_MAGIC_isa,            "isa" },
		{ PERL_MAGIC_dbfile,         "dbfile" },
		{ PERL_MAGIC_shared,         "shared" },
		{ PERL_MAGIC_tied,           "tied" },
		{ PERL_MAGIC_sig,            "sig" },
		{ PERL_MAGIC_uvar,           "uvar" },
		{ PERL_MAGIC_overload_elem,  "overload_elem" },
		{ PERL_MAGIC_overload_table, "overload_table" },
		{ PERL_MAGIC_regdatum,       "regdatum" },
		{ PERL_MAGIC_envelem,        "envelem" },
		{ PERL_MAGIC_fm,             "fm" },
		{ PERL_MAGIC_regex_global,   "regex_global" },
#ifdef PERL_MAGIC_hintelem
		{ PERL_MAGIC_hintselem,      "hintselem" },
#endif
		{ PERL_MAGIC_isaelem,        "isaelem" },
		{ PERL_MAGIC_nkeys,          "nkeys" },
		{ PERL_MAGIC_dbline,         "dbline" },
		{ PERL_MAGIC_shared_scalar,  "shared_scalar" },
		{ PERL_MAGIC_collxfrm,       "collxfrm" },
		{ PERL_MAGIC_tiedelem,       "tiedelem" },
		{ PERL_MAGIC_tiedscalar,     "tiedscalar" },
		{ PERL_MAGIC_qr,             "qr" },
		{ PERL_MAGIC_sigelem,        "sigelem" },
		{ PERL_MAGIC_taint,          "taint" },
		{ PERL_MAGIC_uvar_elem,      "uvar_elem" },
		{ PERL_MAGIC_vec,            "vec" },
		{ PERL_MAGIC_vstring,        "vstring" },
		{ PERL_MAGIC_utf8,           "utf8" },
		{ PERL_MAGIC_substr,         "substr" },
		{ PERL_MAGIC_defelem,        "defelem" },
		{ PERL_MAGIC_ext,            "ext" },
		/* this null string terminates the list */
		{ 0,                         NULL },
	};

	I32 i;
	for(i = 0; magic_names[i].name; i++){
		if(mgtype == magic_names[i].type){
			return magic_names[i].name;
		}
	}
	return form("unknown(%c)", mgtype);
}

#define debsv_impl(sv) do_debsv_impl(aTHX_ aMY_CXT_ seen, sv)
static void
do_debsv_impl(pTHX_ pMY_CXT_ HV* const seen, SV* sv){
	dVAR;
	SV* const buff = MY_CXT.buff;
	HE* he;

	SvGETMAGIC(sv);

	sv_setuv(buff, PTR2UV(sv));
	he = hv_fetch_ent(seen, buff, TRUE, 0U);
	if(SvOK(HeVAL(he))){
		debs("...");
		return;
	}
	sv_setiv(HeVAL(he), TRUE);

	if(SvROK(sv)){
		SV* const rv = SvRV(sv);
		if(SvOBJECT(rv)){
			if(SvAMAGIC(sv)){
				debf("%s=%s(0x%p)", sv_reftype(rv, TRUE), sv_reftype(rv, FALSE), rv);
			}
			else if(SvRXOK(sv)){
				debs("qr/");
				debsv_simple(sv);
				debs("/");
			}
			else{
				debsv_simple(sv);
			}
		}
		else{
			debs("\\");
			debsv_impl(rv);
		}
		goto finish;
	}

	if(SvREADONLY(sv)){
		if(sv == &PL_sv_undef){
			debs("UNDEF");
			return;
		}
		else if(sv == &PL_sv_yes){
			debs("YES");
			return;
		}
		else if(sv == &PL_sv_no){
			debs("NO");
			return;
		}
		else if(sv == &PL_sv_placeholder){
			debs("PLACEHOLDER");
			return;
		}
	}

	if(SvTYPE(sv) == SVt_PVAV){
		I32 const len = AvFILLp((AV*)sv) + 1;
		I32 i;
		debs("@(");
		for(i = 0; i < len; i++){
			debsv_impl(AvARRAY((AV*)sv)[i]);

			if((i+1) < len){
				debs(",");
			}
		}
		debs(")");
	}
	else if(SvTYPE(sv) == SVt_PVHV){
		char* key;
		I32 keylen;
		SV* val;
		SV* const dsv = newSV(PV_LIMIT);
		bool first = TRUE;

		debs("%(");

		hv_iterinit((HV*)sv);
		while((val = hv_iternextsv((HV*)sv, &key, &keylen))){
			if(!first){
				debs(",");
			}
			else{
				first = FALSE;
			}
			pv_pretty(dsv, key, keylen, PV_LIMIT, NULL, NULL, PERL_PV_PRETTY_DUMP);
			debsv_simple(dsv);
			debs("=>");
			debsv_impl(val);
		}

		debs(")");

		SvREFCNT_dec(dsv);
	}
	else if(SvTYPE(sv) == SVt_PVCV || SvTYPE(sv) == SVt_PVFM){
		debgv(CvGV((CV*)sv), "&");
	}
	else if(SvTYPE(sv) == SVt_PVGV){
		debgv((GV*)sv, "*");
	}
	else if(SvTYPE(sv) == SVt_PVIO){
		const PerlIO* const fp = IoIFP((IO*)sv);
		debf("IO(%c 0x%p)", IoTYPE((IO*)sv), fp);
	}
	else{ /* scalar value */
		if(!SvOK(sv)){
			debs("undef");
		}
		else if(SvPOKp(sv)){
			pv_pretty(buff, SvPVX(sv), SvCUR(sv), PV_LIMIT, NULL, NULL, PERL_PV_PRETTY_DUMP);
			debsv_simple(buff);
		}
		else if(SvIOKp(sv)){
			if(SvIsUV(sv)){
				debf("%"UVuf, SvUVX(sv));
			}
			else{
				debf("%"IVdf, SvIVX(sv));
			}
		}
		else if(SvNOKp(sv)){
			debf("%"NVgf, SvNVX(sv));
		}
		else{
			sv_dump(sv);
			croak("panic: unknown scalar value");
		}
	}

	finish:
	if(SvMAGICAL(sv)){
		MAGIC* mg;

		debs(" MG(");
		for(mg = SvMAGIC(sv); mg; mg = mg->mg_moremagic){
			debpv(do_magic_name(mg->mg_type));
			if(mg->mg_moremagic){
				debs(",");
			}
		}
		debs(")");
	}
}

#define debsv(sv) do_debsv(aTHX_ aMY_CXT_ sv)
static void
do_debsv(pTHX_ pMY_CXT_ SV* const sv){
	HV* const seen = MY_CXT.debsv_seen;
	debsv_impl(sv);
	hv_clear(seen);
}

static void
do_stack(pTHX_ pMY_CXT){
	dVAR;
	I32 i = cxstack_ix + 1;
	SV** svp = PL_stack_base + 1;
	SV** end = PL_stack_sp + 1;

	while(--i >= 0){
		debs(" ");
	}

	debs("(");

	while(svp != end){
		debsv(*svp);

		svp++;

		if(svp != end){
			debs(",");
		}
	}

	debs(")\n");
}

/* stolen from dump.c */
#define deb_curcv(ix) S_deb_curcv(aTHX_ ix)
static CV*
S_deb_curcv(pTHX_ const I32 ix)
{
    dVAR;
    const PERL_CONTEXT * const cx = &cxstack[ix];

    if (CxTYPE(cx) == CXt_SUB || CxTYPE(cx) == CXt_FORMAT)
        return cx->blk_sub.cv;
    else if (CxTYPE(cx) == CXt_EVAL && !CxTRYBLOCK(cx))
        return PL_compcv;
    else if (ix == 0 && PL_curstackinfo->si_type == PERLSI_MAIN)
        return PL_main_cv;
    else if (ix <= 0)
        return NULL;
    else
        return deb_curcv(ix - 1);
}

#define debpadname(po) do_debpadname(aTHX_ aMY_CXT_ (po))
static void
do_debpadname(pTHX_ pMY_CXT_ PADOFFSET const targ){
	CV* const cv = deb_curcv(cxstack_ix);
	if(cv){
		SV** const comppad_name = AvARRAY(AvARRAY(CvPADLIST(cv))[0]);
		debsv_simple(comppad_name[targ]);
	}
	else{
		debf("#%u", (unsigned)targ);
	}
}

#define Private(flag, name) STMT_START{ if(o->op_private & (flag)){ debs(name); } } STMT_END

static void
do_optrace(pTHX_ pMY_CXT){
	dVAR;
	const OP* const o = PL_op;
	int i = cxstack_ix + 1;

	while(--i >= 0){
		debs(" ");
	}

	debpv(OP_NAME((OP*)o)); /* OP_NAME requires OP*, not const OP* */

	switch(o->op_type){
	case OP_NEXTSTATE:
	case OP_DBSTATE:
		debf("(%s%s %s:%d)",
			CopLABEL(cCOPo) ? CopLABEL(cCOPo) : "",
			CopSTASHPV(cCOPo),
			CopFILE(cCOPo), (int)CopLINE(cCOPo));
		break;

	case OP_CONST:
		debs("(");
		debsv(cSVOPo_sv);
		debs(")");

#ifdef OPpCONST_NOVER
		Private(OPpCONST_NOVER,        " NOVER");
#endif
		Private(OPpCONST_SHORTCIRCUIT, " SHORTCIRCUIT");
		Private(OPpCONST_STRICT,       " STRICT");
		Private(OPpCONST_ENTERED,      " ENTERED");
		Private(OPpCONST_ARYBASE,      " ARYBASE");
		Private(OPpCONST_BARE,         " BARE");
		Private(OPpCONST_WARNING,      " WARNING");

		break;

	case OP_GV:
	case OP_GVSV:
		debs("(");
		debgv(cGVOPo_gv, (o->op_type == OP_GVSV ? "$" : "*"));
		debs(")");

		if(o->op_type == OP_GV){
			Private(OPpEARLY_CV, " EARLY_CV");
			break;
		}

		/* fall through */
	case OP_RV2SV:
	case OP_RV2AV:
	case OP_RV2HV:

		Private(OPpLVAL_INTRO, " LVAL_INTRO");
		Private(OPpOUR_INTRO,  " OUR_INTRO");
		Private(OPpDEREF,      " DEREF");
		break;

	case OP_PADSV:
	case OP_PADAV:
	case OP_PADHV:
		debs("(");
		debpadname(o->op_targ);
		debs(")");

		Private(OPpLVAL_INTRO, " LVAL_INTRO");
#ifdef OPpPAD_STATE
		Private(OPpPAD_STATE,  " STATE");
#endif
		Private(OPpDEREF,      " DEREF");

		break;

	case OP_AELEMFAST:
		debs("(");
		if(o->op_flags & OPf_SPECIAL){
			debpadname(o->op_targ);
		}
		else{
			debgv(cGVOPo_gv, "@");
		}
		debf("[%d])", (int)o->op_private);
		break;

	case OP_AELEM:
	case OP_HELEM:
		Private(OPpLVAL_INTRO, " LVAL_INTRO");
		Private(OPpDEREF,      " DEREF");
		break;

	case OP_ENTERITER:
		if(o->op_targ){ /* foreach my $var(...) */
			debs("(");
			debpadname(o->op_targ);
			debs(")");
		}

#ifdef OPpITER_DEF
		Private(OPpITER_DEF,      " DEF");
#endif
		Private(OPpLVAL_INTRO,    " LVAL_INTRO");
		Private(OPpOUR_INTRO,     " OUR_INTRO");
		Private(OPpITER_REVERSED, " REVERSED");
		break;

	case OP_ENTERSUB:
	{
		Private(OPpENTERSUB_DB,      " DB");
		Private(OPpENTERSUB_HASTARG, " HASTARG");
		Private(OPpENTERSUB_NOMOD,   " NOMOD");
	}

		/* fall through */
	case OP_RV2CV:
		Private(OPpENTERSUB_AMPER,   " AMPER");
		Private(OPpENTERSUB_NOPAREN, " NOPAREN");
		Private(OPpENTERSUB_INARGS,  " INARGS");

		if(o->op_type == OP_RV2CV){
#ifdef OPpMAY_RETURN_CONSTANT
			Private(OPpMAY_RETURN_CONSTANT,   " MAY_RETURN_CONSTANT");
#endif
		}
		break;

	case OP_SASSIGN:
		Private(OPpASSIGN_BACKWARDS, " BACKWARDS");
#ifdef OPpASSIGN_CV_TO_GV
		Private(OPpASSIGN_CV_TO_GV,  " CV_TO_GV");
#endif
		break;

	case OP_AASSIGN:
		Private(OPpASSIGN_COMMON, " COMMON");
		break;

	case OP_METHOD_NAMED:
		debs("(");
		debsv_simple(cSVOPo_sv);
		debs(")");
		break;

	case OP_TRANS:
		Private(OPpTRANS_TO_UTF,     " TO_UTF");
		Private(OPpTRANS_IDENTICAL,  " IDENTICAL");
		Private(OPpTRANS_SQUASH,     " SQUASH");
		Private(OPpTRANS_COMPLEMENT, " COMPLEMENT");
		Private(OPpTRANS_GROWS,      " GROWS");
		Private(OPpTRANS_DELETE,     " DELETE");
		break;
	default:
		NOOP;
	}

	/* flags */
	if((o->op_flags & OPf_WANT) == OPf_WANT_VOID){
		debs(" VOID");
	}
	else if((o->op_flags & OPf_WANT) == OPf_WANT_SCALAR){
		debs(" SCALAR");
	}
	else if((o->op_flags & OPf_WANT) == OPf_WANT_LIST){
		debs(" LIST");
	}

	if(o->op_flags & OPf_KIDS){
		debs(" KIDS");
	}
	if(o->op_flags & OPf_PARENS){
		debs(" PARENS");
	}
	if(o->op_flags & OPf_REF){
		debs(" REF");
	}
	if(o->op_flags & OPf_MOD){
		debs(" MOD");
	}
	if(o->op_flags & OPf_STACKED){
		debs(" STACKED");
	}
	if(o->op_flags & OPf_SPECIAL){
		debs(" SPECIAL");
	}

	debs("\n");
}

static int
d_optrace_runops(pTHX)
{
	dVAR;
	dMY_DEBUG;

	if(DO_RUNOPS){
		debf("Entering RUNOPS (%s:%d)\n", CopFILE(PL_curcop), (int)CopLINE(PL_curcop));
	}

	do{
		PERL_ASYNC_CHECK();

		if(DO_STACK){
			do_stack(aTHX_ aMY_CXT);
		}
		if(DO_TRACE){
			do_optrace(aTHX_ aMY_CXT);
		}
	}
	while((PL_op = CALL_FPTR(PL_op->op_ppaddr)(aTHX)));

	if(DO_STACK){
		do_stack(aTHX_ aMY_CXT);
	}

	if(DO_RUNOPS){
		debf("Leaving RUNOPS (%s:%d)\n", CopFILE(PL_curcop), (int)CopLINE(PL_curcop));
	}

	TAINT_NOT;
	return 0;
}

static void
d_optrace_peep(pTHX_ OP* const o){
	dMY_DEBUG;

	if(!DO_NOOPT){
		MY_CXT.orig_peepp(aTHX_ o);
	}
}

static void
do_uninit_debugger(pTHX){
	dVAR;

#if 0
	PL_dbargs   = NULL; /* @DB::args */
	PL_DBgv     = NULL; /* *DB::DB */
	PL_DBline   = NULL; /* *DB::line */
	PL_DBsub    = NULL; /* *DB::sub */
	PL_DBsingle = NULL; /* $DB::single */
	PL_DBtrace  = NULL; /* $DB::trace */
	PL_DBsignal = NULL; /* $DB::signal */
#endif

	PL_perldb   = (PERLDBf_NAMEEVAL | PERLDBf_NAMEANON); /* $^P */
}

MODULE = Devel::Optrace	PACKAGE = Devel::Optrace

BOOT:
{
	HV* const stash = gv_stashpvs(PACKAGE, TRUE);
	MY_CXT_INIT;
	MY_CXT.debugsv = get_sv(PACKAGE "::DB", GV_ADD);
	if(!SvOK(MY_CXT.debugsv)){
		sv_setiv(MY_CXT.debugsv, 0x00);
	}

	MY_CXT.log        = Perl_error_log;
	MY_CXT.buff       = newSV(50);
	MY_CXT.debf_buff  = newSV(50);
	MY_CXT.debsv_seen = newHV();

	MY_CXT.orig_runops = PL_runops;
	MY_CXT.orig_peepp  = PL_peepp;

	if(PL_perldb){
		do_uninit_debugger(aTHX);
	}

	newCONSTSUB(stash, "DOf_TRACE",   newSViv(DOf_TRACE));
	newCONSTSUB(stash, "DOf_STACK",   newSViv(DOf_STACK));
	newCONSTSUB(stash, "DOf_RUNOPS",  newSViv(DOf_RUNOPS));
	newCONSTSUB(stash, "DOf_NOOPT",   newSViv(DOf_NOOPT));

	newCONSTSUB(stash, "DOf_ALL",     newSViv(DOf_ALL));

	PL_runops = d_optrace_runops;
	PL_peepp  = d_optrace_peep;
}

PROTOTYPES: DISABLE

void
p(...)
CODE:
{
	dMY_CXT;
	while(MARK != SP){
		debsv(*(++MARK));
		debs("\n");
	}
	PERL_UNUSED_VAR(items);
}

