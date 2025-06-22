package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	// "encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/yusufpapurcu/wmi"
)

type CIM_Processor struct {
	LoadPercentage int64
}

type Metrics struct {
	CPU          float32
	MemorySize   float32
	MemoryFree   float32
	MemoryPerc   float32
	DiskMetrics  []DiskMetric
	LicenseCount int
	Uptime       int
	BootTime     string
	DBfiles      []DBfile
}

type DiskMetric struct {
	DiskName     string
	DiskSize     float32
	DiskFree     float32
	DiskUsed     float32
	DiskUsedPerc float32
	DiskFreePerc float32
}
type DBfile struct {
	Name         string
	LastModified string
	Size         float32
}

type Config struct {
	ServerURL  string
	ServerCode string
	UserName   string
	Password   string
	Interval   time.Duration
	LDF        string
	MDF        string
	NDF        []string
}
type Payload struct {
	ServerCode string
	TimeStamp  time.Time
	Metrics    Metrics
}

var token string
var expiryTime time.Time

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "config" {
			Configure()
			return
		}
	}

	conf := ReadConfig()
	fmt.Println(conf.NDF)

	for {
		payload := Payload{}
		payload.ServerCode = conf.ServerCode
		payload.Metrics = GetMetrics(conf)

		payload.TimeStamp = time.Now()

		//Call API to post the payload
		PostMetrics(conf, payload)
		time.Sleep(conf.Interval)
		//fmt.Println(payload)
	}

}

func ReadConfig() Config {
	conf := Config{}
	byts, _ := ioutil.ReadFile("metrics.conf")
	json.Unmarshal(byts, &conf)
	return conf
}

func Configure() {
	conf := Config{}
	var n int
	var path, IsDB string
	var paths []string
	fmt.Println("Enter Server Url")
	fmt.Scan(&conf.ServerURL)
	fmt.Scanln()
	fmt.Println("Enter Server Code")
	fmt.Scan(&conf.ServerCode)
	fmt.Scanln()

	fmt.Println("Enter User Name")
	fmt.Scan(&conf.UserName)
	fmt.Scanln()
	fmt.Println("Enter Password")
	fmt.Scan(&conf.Password)
	fmt.Scanln()
	fmt.Println("Enter Interval for Eg. 2h or 5m or 30s")
	intv := "45s"
	fmt.Scan(&intv)
	fmt.Scanln()
	conf.Interval, _ = time.ParseDuration(intv)
	fmt.Println("Whether this server is DB server? (type YES or NO)")
	fmt.Scan(&IsDB)
	fmt.Scanln()
	if strings.TrimSpace(strings.ToLower(IsDB)) == "yes" {
		fmt.Println("Enter LDF path")
		fmt.Scan(&conf.LDF)
		fmt.Scanln()
		fmt.Println("Enter MDF path")
		fmt.Scan(&conf.MDF)
		fmt.Scanln()
		fmt.Println("No.of NDF files")
		fmt.Scan(&n)
		fmt.Scanln()
		if n > 0 {
			var i int
			for i = 1; i <= n; i++ {
				fmt.Println(fmt.Sprintf("NDF path %d", i))
				fmt.Scan(&path)
				paths = append(paths, path)

			}
			conf.NDF = paths

		}

	}
	//fmt.Println(conf)

	fmt.Print(conf)
	//Store in Json file
	cont, _ := json.Marshal(conf)
	ioutil.WriteFile("metrics.conf", cont, 0777)
}

func GetMetrics(conf Config) Metrics {

	metrics := Metrics{}
	sysinfo, _ := host.Info()
	dbf := DBfile{}

	var dst []CIM_Processor
	err := wmi.Query("SELECT LoadPercentage FROM CIM_Processor", &dst)

	fmt.Println(dst)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("CPU Utilization%:", dst[0].LoadPercentage)
	metrics.CPU = float32(dst[0].LoadPercentage)
	//percent, _ := cpu.Percent(0, true)
	// fmt.Println("CPU Utilization%:", percent[cpu.InfoStat{}.CPU])
	// metrics.CPU = float32(percent[cpu.InfoStat{}.CPU])

	v, _ := mem.VirtualMemory()

	// almost every return value is a struct
	// fmt.Printf("Total: %v, Free:%v, UsedPercent:%f%%\n", v.Total, v.Free, v.UsedPercent)

	metrics.MemorySize = float32(v.Total) / 1073741824
	metrics.MemoryFree = float32(v.Free) / 1073741824
	metrics.MemoryPerc = float32(v.UsedPercent)

	partitions, _ := disk.Partitions(true)
	for _, part := range partitions {
		dm := DiskMetric{}
		diskStat, err := disk.Usage(part.Mountpoint)
		if err != nil {
			log.Println(err)
			continue
		}
		dm.DiskName = part.Mountpoint
		dm.DiskSize = float32(diskStat.Total) / 1073741824
		dm.DiskFree = float32(diskStat.Free) / 1073741824
		dm.DiskUsed = float32(diskStat.Used) / 1073741824
		dm.DiskFreePerc = float32(float64(diskStat.Free) / float64(diskStat.Total) * 100)
		dm.DiskUsedPerc = float32(float64(diskStat.Used) / float64(diskStat.Total) * 100)

		metrics.DiskMetrics = append(metrics.DiskMetrics, dm)
	}
	// metrics.LicenseCount = GetLNLicenseCount()
	// mbs, _ := json.Marshal(metrics)
	// fmt.Println(string(mbs))

	//Uptime & Boottime
	metrics.BootTime = time.Unix(int64(sysinfo.BootTime), 1).Format("2006-01-02 15:04:05")
	metrics.Uptime = int(sysinfo.Uptime) / (3600 * 24)

	//DBfiles

	//LDF file
	if conf.LDF != "" {

		df_file, err := os.Stat(conf.LDF)
		if err != nil {
			panic("Cannot get LDF info")
		}
		dbf.Name = df_file.Name()
		dbf.Size = float32(df_file.Size()) / 1073741824
		dbf.LastModified = df_file.ModTime().Format("2006-01-02 15:04:05")
		metrics.DBfiles = append(metrics.DBfiles, dbf)

		//MDF file
		df_file, err = os.Stat(conf.MDF)
		if err != nil {
			panic("Cannot get MDF info")
		}
		dbf.Name = df_file.Name()
		dbf.Size = float32(df_file.Size()) / 1073741824
		dbf.LastModified = df_file.ModTime().Format("2006-01-02 15:04:05")
		metrics.DBfiles = append(metrics.DBfiles, dbf)
	}
	//NDF files
	if len(conf.NDF) != 0 {

		for _, ndf := range conf.NDF {

			df_file, err := os.Stat(ndf)
			if err != nil {
				panic("Cannot get NDF info")
			}
			dbf.Name = df_file.Name()
			dbf.Size = float32(df_file.Size()) / 1073741824
			dbf.LastModified = df_file.ModTime().Format("2006-01-02 15:04:05")
			metrics.DBfiles = append(metrics.DBfiles, dbf)
		}
	}
	return metrics
}

func PostMetrics(conf Config, data Payload) {

	if token == "" || expiryTime.Sub(time.Now()) < (time.Second) {
		Authenticate(conf)
	}

	url := conf.ServerURL + "/api/execbo/metrics/post"
	method := "POST"
	byts, _ := json.Marshal(data)
	payload := strings.NewReader(string(byts))

	client := &http.Client{}

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", token)
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	log.Println(string(body))

}

func Authenticate(conf Config) {
	log.Println("Authenticating...")
	url := conf.ServerURL + "/api/signin"
	method := "POST"
	cred := make(map[string]string)
	cred["username"] = conf.UserName
	cred["password"] = conf.Password
	byts, _ := json.Marshal(cred)
	payload := strings.NewReader(string(byts))
	fmt.Println(string(byts))

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	resp := AuthResponse{}

	if err != nil {
		fmt.Println(err)
		return
	}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Println("Authenticated...")
	token = resp.Token
	expiryTime = resp.ExpiresAt
}

type AuthResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:expiresAt`
}

type Win32_Process struct {
	Name      string
	ProcessID int64
	//CommandLine string
}

func GetLNLicenseCount() int {
	var dst []Win32_Process
	q := wmi.CreateQuery(&dst, " WHERE Name = 'ntbshell.exe'")
	//fmt.Println(q)
	err := wmi.Query(q, &dst)
	if err != nil {
		fmt.Println("Error Finding ntbshells", err)
		return 0
	}
	//var pids []int64
	//fmt.Println(len(dst))
	return len(dst)
	//return rand.Intn(25)
}
