package main

/*
#ifndef _LIBCORAZA_H_
#define _LIBCORAZA_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct coraza_intervention_t
{
	char *action;
	char *log;
    char *url;
    int status;
    int pause;
    int disruptive;
} coraza_intervention_t;

typedef uint64_t coraza_waf_t;
typedef uint64_t coraza_transaction_t;

typedef void (*coraza_log_cb) (const void *);
void send_log_to_cb(coraza_log_cb cb, const char *msg);
#endif
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

var wafMap = make(map[uint64]coraza.WAF)
var txMap = make(map[uint64]types.Transaction)

type MessageData struct {
	Message   string             `json:"message"`
	ID_       int                `json:"id"`
	Rev_      string             `json:"rev"`
	Ver_      string             `json:"ver"`
	Data_     []string           `json:"data"`
	Severity_ types.RuleSeverity `json:"severity"`
	Maturity_ int                `json:"maturity"`
	Accuracy_ int                `json:"accuracy"`
	Tags_     []string           `json:"tags"`
}

/**
 * Creates a new  WAF instance
 * @returns pointer to WAF instance
 */
//export coraza_new_waf
func coraza_new_waf() C.coraza_waf_t {
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig())
	ptr := wafToPtr(waf)
	wafMap[ptr] = waf
	return C.coraza_waf_t(ptr)
}

/**
 * Creates a new transaction for a WAF instance
 * @param[in] pointer to valid WAF instance
 * @param[in] pointer to log callback, can be null
 * @returns pointer to transaction
 */
//export coraza_new_transaction
func coraza_new_transaction(waf C.coraza_waf_t, logCb unsafe.Pointer) C.coraza_transaction_t {
	w := ptrToWaf(waf)
	tx := w.NewTransaction()
	ptr := transactionToPtr(tx)
	txMap[ptr] = tx
	return C.coraza_transaction_t(ptr)
}

//export coraza_new_transaction_with_id
func coraza_new_transaction_with_id(waf C.coraza_waf_t, id *C.char, logCb unsafe.Pointer) C.coraza_transaction_t {
	w := ptrToWaf(waf)
	tx := w.NewTransactionWithID(cStringToGoString(id))
	ptr := transactionToPtr(tx)
	txMap[ptr] = tx
	return C.coraza_transaction_t(ptr)
}

//export coraza_intervention
func coraza_intervention(tx C.coraza_transaction_t) *C.coraza_intervention_t {
	t := ptrToTransaction(tx)
	if t.Interruption() == nil {
		return nil
	}
	mem := (*C.coraza_intervention_t)(C.malloc(C.size_t(unsafe.Sizeof(C.coraza_intervention_t{}))))
	mem.action = C.CString(t.Interruption().Action)
	mem.status = C.int(t.Interruption().Status)
	return mem
}

//export coraza_process_connection
func coraza_process_connection(t C.coraza_transaction_t, sourceAddress *C.char, clientPort C.int, serverHost *C.char, serverPort C.int) C.int {
	tx := ptrToTransaction(t)
	srcAddr := cStringToGoString(sourceAddress)
	cp := int(clientPort)
	ch := cStringToGoString(serverHost)
	sp := int(serverPort)
	tx.ProcessConnection(srcAddr, cp, ch, sp)
	return 0
}

//export coraza_process_request_body
func coraza_process_request_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessRequestBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_update_status_code
func coraza_update_status_code(t C.coraza_transaction_t, code C.int) C.int {
	// tx := ptrToTransaction(t)
	// c := strconv.Itoa(int(code))
	// tx.Variables.ResponseStatus.Set(c)
	return 0
}

// msr->t, r->unparsed_uri, r->method, r->protocol + offset
//
//export coraza_process_uri
func coraza_process_uri(t C.coraza_transaction_t, uri *C.char, method *C.char, proto *C.char) C.int {
	tx := ptrToTransaction(t)

	tx.ProcessURI(cStringToGoString(uri), cStringToGoString(method), cStringToGoString(proto))
	return 0
}

//export coraza_add_request_header
func coraza_add_request_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddRequestHeader(cStringToGoStringN(name, name_len), cStringToGoStringN(value, value_len))
	return 0
}

//export coraza_process_request_headers
func coraza_process_request_headers(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessRequestHeaders()
	return 0
}

//export coraza_process_logging
func coraza_process_logging(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessLogging()
	return 0
}

//export coraza_add_get_args
func coraza_add_get_args(t C.coraza_transaction_t, name *C.char, value *C.char) C.int {
	tx := ptrToTransaction(t)
	tx.AddGetRequestArgument(cStringToGoString(name), cStringToGoString(value))
	return 0
}

//export coraza_append_request_body
func coraza_append_request_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteRequestBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_add_response_header
func coraza_add_response_header(t C.coraza_transaction_t, name *C.char, name_len C.int, value *C.char, value_len C.int) C.int {
	tx := ptrToTransaction(t)
	tx.AddResponseHeader(cStringToGoStringN(name, name_len), cStringToGoStringN(value, value_len))
	return 0
}

//export coraza_append_response_body
func coraza_append_response_body(t C.coraza_transaction_t, data *C.uchar, length C.int) C.int {
	tx := ptrToTransaction(t)
	if _, _, err := tx.WriteResponseBody(C.GoBytes(unsafe.Pointer(data), length)); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_body
func coraza_process_response_body(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if _, err := tx.ProcessResponseBody(); err != nil {
		return 1
	}
	return 0
}

//export coraza_process_response_headers
func coraza_process_response_headers(t C.coraza_transaction_t, status C.int, proto *C.char) C.int {
	tx := ptrToTransaction(t)
	tx.ProcessResponseHeaders(int(status), cStringToGoString(proto))
	return 0
}

type Parser struct{}

//go:linkname NewParser github.com/corazawaf/coraza/v3/internal/seclang.NewParser
func NewParser(waf *coraza.WAF) *Parser

//go:linkname FromFile github.com/corazawaf/coraza/v3/internal/seclang.(*Parser).FromFile
func FromFile(p *Parser, profilePath string) error

//go:linkname FromString github.com/corazawaf/coraza/v3/internal/seclang.(*Parser).FromString
func FromString(p *Parser, data string) error

//export coraza_rules_add_file
func coraza_rules_add_file(w C.coraza_waf_t, file *C.char, er **C.char) C.int {
	waf := ptrToWaf(w)
	value := reflect.ValueOf(waf)
	innerWaf := (*coraza.WAF)(value.FieldByName("waf").UnsafePointer())
	parser := NewParser(innerWaf)
	err := FromFile(parser, cStringToGoString(file))
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	return 1
}

//export coraza_rules_add
func coraza_rules_add(w C.coraza_waf_t, directives *C.char, er **C.char) C.int {
	waf := ptrToWaf(w)
	value := reflect.ValueOf(waf)
	innerWaf := (*coraza.WAF)(value.FieldByName("waf").UnsafePointer())
	parser := NewParser(innerWaf)
	err := FromString(parser, cStringToGoString(directives))
	if err != nil {
		*er = C.CString(err.Error())
		// we share the pointer, so we shouldn't free it, right?
		return 0
	}
	return 1
}

//export coraza_rules_count
func coraza_rules_count(w C.coraza_waf_t) C.int {
	return 0
}

//export coraza_free_transaction
func coraza_free_transaction(t C.coraza_transaction_t) C.int {
	tx := ptrToTransaction(t)
	if tx.Close() != nil {
		return 1
	}
	delete(txMap, uint64(t))
	return 0
}

//export coraza_free_intervention
func coraza_free_intervention(it *C.coraza_intervention_t) C.int {
	if it == nil {
		return 1
	}
	defer C.free(unsafe.Pointer(it))
	// C.free(unsafe.Pointer(it.log))
	// C.free(unsafe.Pointer(it.url))
	C.free(unsafe.Pointer(it.action))
	return 0
}

//export coraza_rules_merge
func coraza_rules_merge(w1 C.coraza_waf_t, w2 C.coraza_waf_t, er **C.char) C.int {
	return 0
}

//export coraza_request_body_from_file
func coraza_request_body_from_file(t C.coraza_transaction_t, file *C.char) C.int {
	tx := ptrToTransaction(t)
	f, err := os.Open(cStringToGoString(file))
	if err != nil {
		return 1
	}
	defer f.Close()
	// we read the file in chunks and send it to the engine
	for {
		buf := make([]byte, 1024)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 1
		}
		if _, _, err := tx.WriteRequestBody(buf[:n]); err != nil {
			return 1
		}
	}
	return 0
}

//export coraza_free_waf
func coraza_free_waf(t C.coraza_waf_t) C.int {
	// waf := ptrToWaf(t)
	delete(wafMap, uint64(t))
	return 0
}

//export coraza_set_log_cb
func coraza_set_log_cb(waf C.coraza_waf_t, cb C.coraza_log_cb) {
}

/**
 * 获取匹配到的规则log日志，这里只返回规则中非nolog的日志。调用完成后记得调用coraza_free_matched_logmsg方法去free掉。
 * 如果匹配到的内容为空，那么返回""
 * @returns pointer to logmsg
 */
//export coraza_get_matched_logmsg
func coraza_get_matched_logmsg(t C.coraza_transaction_t) *C.char {
	tx := ptrToTransaction(t)
	if len(tx.MatchedRules()) == 0 {
		return C.CString("")
	}
	// we need to build a json object with the matched rules
	// and the corresponding data
	var logData []byte
	var err error
	message := make([]MessageData, 0)
	for _, mr := range tx.MatchedRules() {
		r := mr.Rule().(*corazawaf.Rule)
		if !r.Log && !r.Audit {
			// 说明被匹配到的规则是nolog类型，不需要返回给调用人员
			continue
		}

		matchData := make([]string, 0, 10)
		for _, i := range mr.MatchedDatas() {
			matchData = append(matchData, fmt.Sprintf("%s: %s", i.Key(), i.Value()))
		}
		message = append(message, MessageData{
			Message:   mr.Message(),
			ID_:       r.ID(),
			Rev_:      r.Revision(),
			Ver_:      r.Version(),
			Data_:     matchData,
			Severity_: r.Severity(),
			Maturity_: r.Maturity(),
			Accuracy_: r.Accuracy(),
			Tags_:     r.Tags(),
		})
	}
	if logData, err = json.Marshal(message); err != nil {
		return C.CString("")
	}

	return C.CString(string(logData))
}

/**
 * 释放coraza_free_matched_logmsg方法得到的内存。
 * 如果失败，返回1，成功返回0
 * @returns pointer to logmsg
 */
//export coraza_free_matched_logmsg
func coraza_free_matched_logmsg(t *C.char) C.int {
	if t == nil {
		return 1
	}
	C.free(unsafe.Pointer(t))
	return 0
}

/*
Internal helpers
*/

func ptrToWaf(waf C.coraza_waf_t) coraza.WAF {
	return wafMap[uint64(waf)]
}

func ptrToTransaction(t C.coraza_transaction_t) types.Transaction {
	return txMap[uint64(t)]
}

func transactionToPtr(tx types.Transaction) uint64 {
	return uint64(reflect.ValueOf(&tx).Pointer())
}

func wafToPtr(waf coraza.WAF) uint64 {
	return uint64(reflect.ValueOf(&waf).Pointer())
}

// It should just be C.CString(s) but we need this to build tests
func stringToC(s string) *C.char {
	return C.CString(s)
}

func intToCint(i int) C.int {
	return C.int(i)
}

// cStringToGoString converts C string to Go string without copying data to enhance performance.
func cStringToGoString(cStr *C.char) string {

	myStr := new(reflect.StringHeader)
	// size_t strnlen(const char *s, size_t max_len);
	cStrLen := C.strnlen(cStr, 65535) // invoke strnlen to obtain the len of cStr

	myStr.Data = (uintptr)(unsafe.Pointer(cStr)) // the pointer of c char*
	myStr.Len = int(cStrLen)                     // the length of c char *
	gostr := *(*string)(unsafe.Pointer(myStr))
	return gostr
}

func cStringToGoStringN(cStr *C.char, cLen C.int) string {
	myStr := new(reflect.StringHeader)
	myStr.Data = (uintptr)(unsafe.Pointer(cStr)) // the pointer of c char*
	myStr.Len = int(cLen)                        // the length of c char *
	gostr := *(*string)(unsafe.Pointer(myStr))
	return gostr
}

func main() {}
