package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG701Concurrency holds whole-program, cross-goroutine taint
// fixtures. Unlike the single-function G701 set, these exercise data that
// crosses goroutine, channel and thread-safe-container boundaries — the forms
// a demand-driven, function-local engine cannot follow. Each positive sample
// must be reported with a full propagation trace; each negative sample (a
// sanitizer on either side of the boundary, or constant data) must report
// nothing.
var SampleCodeG701Concurrency = []CodeSample{
	// 1. Unbuffered channel: producer goroutine and receiver goroutine.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func channelWorker(ch chan string, db *sql.DB) {
	orderID := <-ch
	db.Exec("DELETE FROM orders WHERE id = '" + orderID + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan string)
	go channelWorker(ch, db)
	ch <- r.FormValue("id")
}
`}, 1, gosec.NewConfig()},

	// 2. Buffered channel fan-out across three workers.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func fanoutWorker(ch chan string, db *sql.DB) {
	v := <-ch
	db.Exec("SELECT * FROM t WHERE v = '" + v + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan string, 3)
	go fanoutWorker(ch, db)
	go fanoutWorker(ch, db)
	go fanoutWorker(ch, db)
	ch <- r.FormValue("v")
}
`}, 1, gosec.NewConfig()},

	// 3. Fan-in: multiple producers, one consumer reaching the sink.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func orderProducer(ch chan<- string, r *http.Request) {
	ch <- r.FormValue("order")
}

func orderConsumer(ch <-chan string, db *sql.DB) {
	db.Exec("UPDATE orders SET n = '" + <-ch + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan string)
	go orderProducer(ch, r)
	go orderProducer(ch, r)
	go orderConsumer(ch, db)
}
`}, 1, gosec.NewConfig()},

	// 4. Struct field carried through a channel.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Order struct {
	ID string
}

func structWorker(ch chan *Order, db *sql.DB) {
	order := <-ch
	db.Exec("DELETE FROM orders WHERE id = '" + order.ID + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan *Order)
	go structWorker(ch, db)
	ch <- &Order{ID: r.FormValue("id")}
}
`}, 1, gosec.NewConfig()},

	// 5. Slice element carried through a channel.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func sliceWorker(ch chan []string, db *sql.DB) {
	ids := <-ch
	db.Exec("DELETE FROM t WHERE id = '" + ids[0] + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan []string, 1)
	go sliceWorker(ch, db)
	ch <- []string{r.FormValue("id")}
}
`}, 1, gosec.NewConfig()},

	// 6. Map value carried through a channel.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func mapWorker(ch chan map[string]string, db *sql.DB) {
	m := <-ch
	db.Exec("DELETE FROM t WHERE id = '" + m["id"] + "'")
}

func handler(db *sql.DB, r *http.Request) {
	ch := make(chan map[string]string, 1)
	go mapWorker(ch, db)
	ch <- map[string]string{"id": r.FormValue("id")}
}
`}, 1, gosec.NewConfig()},

	// 7. Interface method return keeps taint across the goroutine boundary.
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Carrier interface {
	Payload() string
}

type orderCarrier struct {
	value string
}

func (c *orderCarrier) Payload() string { return c.value }

func interfaceWorker(c Carrier, db *sql.DB) {
	db.Exec("DELETE FROM t WHERE v = '" + c.Payload() + "'")
}

func handler(db *sql.DB, r *http.Request) {
	c := &orderCarrier{value: r.FormValue("v")}
	go interfaceWorker(c, db)
}
`}, 1, gosec.NewConfig()},

	// 8. Negative: data that never touches a request stays clean even though
	// it crosses the same channel/goroutine boundary.
	{[]string{`
package main

import (
	"database/sql"
)

func safeWorker(ch chan string, db *sql.DB) {
	db.Exec("DELETE FROM t WHERE v = '" + <-ch + "'")
}

func localValue() string {
	return "internal-value"
}

func handler(db *sql.DB) {
	ch := make(chan string, 1)
	go safeWorker(ch, db)
	ch <- localValue()
}
`}, 0, gosec.NewConfig()},

	// 9. Negative: constant data through the channel is never tainted.
	{[]string{`
package main

import (
	"database/sql"
)

func constWorker(ch chan string, db *sql.DB) {
	db.Exec("DELETE FROM t WHERE v = '" + <-ch + "'")
}

func handler(db *sql.DB) {
	ch := make(chan string, 1)
	go constWorker(ch, db)
	ch <- "hardcoded-value"
}
`}, 0, gosec.NewConfig()},
}
