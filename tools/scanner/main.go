package main

import (
	"flag"
	"fmt"
	"sync"
	"time"

	redis "github.com/gomodule/redigo/redis"

	"github.com/branthz/utarrow/lib/util"
)

var ipStart = flag.String("ip", "119.2.0.0", "ip start from")
var scale = flag.Int("lth", 10000, "length")

func dialPort(ip string) {
	var tout time.Duration = 3 * 1e9
	conn, err := redis.DialTimeout("tcp", ip+":6379", tout, tout, tout)
	if err != nil {
		wg.Done()
		return
	}
	_, err = conn.Do("ping")
	if err != nil {
		wg.Done()
		return
	}
	conn.Close()
	fmt.Println(ip)
	wg.Done()
	return
}

const step = 2000

var wg sync.WaitGroup

func hah() {
	var tout time.Duration = 3 * 1e9
	var ip = "192.168.29.89"
	conn, err := redis.DialTimeout("tcp", ip+":6379", tout, tout, tout)
	if err != nil {
		return
	}
	_, err = conn.Do("ping")
	if err != nil {
		return
	}
	conn.Close()
	fmt.Println(ip)
	return

}

func main() {
	flag.Parse()
	ipI := util.Ip2int(*ipStart)

	ipE := ipI + *scale
	for i := ipI; i < ipE; {
		for j := 0; j < step; j++ {
			wg.Add(1)
			ip := util.Int2ip(i + j)
			go dialPort(ip)
		}
		i += step
		wg.Wait()
	}
}
