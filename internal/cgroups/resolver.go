// Package cgroups — cekirdegin verdigi sayiyi Kubernetes kimligine cevirir.
//
// # NE ISE YARIYOR
//
// eBPF bize cgroup_id veriyor: 64 bitlik bir sayi, pod adi degil. Bu paket
// o sayiyi once bir cgroupfs yoluna, oradan da pod UID + container ID'ye
// ceviriyor. Onsuz akislar "bir yerden bir yere" olurdu; bununla "su pod'dan
// su adrese" oluyor.
//
// # NASIL CALISIYOR
//
// Kubernetes API'sine HIC BASVURMUYOR. Yontem su gozleme dayaniyor:
// cgroupfs'te bir dizinin dosya tanitici (file handle) degeri, BPF
// tarafindaki bpf_get_current_cgroup_id() ile AYNI 64-bit kimligi tasiyor.
// Yani /sys/fs/cgroup agacini gezip her dizinin kimligini okuyarak
// kimlik -> yol haritasi kurulabiliyor. Yolun icinde pod UID ve container ID
// zaten yaziyor.
//
// API'ye basvurmamak bilincli: probe her dugumde root olarak calisacak ve
// her olay icin apiserver'a sorgu atmak hem gecikme hem yuk anlaminda
// kabul edilemez. Ustelik kubelet cokse bile bu yontem calismaya devam eder.
//
// # NEDEN YENIDEN TARAMA VAR
//
// Pod'lar surekli yaratilip siliniyor; bir kez taranan harita hemen
// bayatliyor. Bulunamayan her kimlikte agaci bastan taramak ise pahali
// (binlerce dizin). minRescan bu ikisi arasinda denge kuruyor: bilinmeyen
// bir kimlik gelirse yeniden tara, ama saniyede bir defadan fazla degil.
//
// # SINIRI
//
// Yol bir Kubernetes is yukune ait olmayabilir -- sistem servisleri,
// kullanici oturumlari. Parse() o durumda bos alanlar dondurur; olay yine
// yayinlanir, yalnizca pod eslestirmesi yapilamaz.
package cgroups

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultRoot, cgroup v2 birlesik hiyerarsisinin olagan yeri.
const DefaultRoot = "/sys/fs/cgroup"

// minRescan — bulunamayan her kimlik icin butun agaci yeniden taramayi
// engelleyen alt sinir. Bilinmeyen kimlik akini (yeni pod dalgasi) geldiginde
// tarama maliyeti saniyede bir defayla sinirli kaliyor.
const minRescan = 2 * time.Second

// Resolver, cgroup id -> yol haritasini tutar.
type Resolver struct {
	root string

	mu       sync.Mutex
	paths    map[uint64]string
	lastScan time.Time
}

func New(root string) *Resolver {
	if root == "" {
		root = DefaultRoot
	}
	return &Resolver{root: root, paths: make(map[uint64]string)}
}

// Path, kimlige karsilik gelen cgroup yolunu (root'a gore) dondurur.
func (r *Resolver) Path(id uint64) (string, bool) {
	if id == 0 {
		return "", false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if p, ok := r.paths[id]; ok {
		return p, true
	}
	if time.Since(r.lastScan) < minRescan {
		return "", false
	}
	r.scan()
	p, ok := r.paths[id]
	return p, ok
}

// scan, cagiran tarafindan kilitlenmis olmali.
func (r *Resolver) scan() {
	r.lastScan = time.Now()
	next := make(map[uint64]string, len(r.paths))

	// Tarama sirasinda kaybolan cgroup'lar olagan (pod'lar siliniyor); tekil
	// hatalari yutup taramayi surduruyoruz.
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // silinmis dizin, atla
		}
		if !d.IsDir() {
			return nil
		}
		id, err := cgroupID(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(r.root, path)
		if err != nil {
			return nil
		}
		next[id] = "/" + filepath.ToSlash(rel)
		return nil
	})

	if len(next) > 0 {
		r.paths = next
	}
}

// cgroupID — bir cgroup dizininin cekirdek ic kimligini okur.
//
// name_to_handle_at(2) cgroupfs uzerinde dizinin inode benzeri 64-bit
// kimligini dondurur ve bu deger BPF tarafindaki
// bpf_get_current_cgroup_id() ile ayni. Butun eslestirme bu esitlige
// dayaniyor.
func cgroupID(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, err
	}
	b := handle.Bytes()
	if len(b) < 8 {
		return 0, unix.EINVAL
	}
	// Handle icerigi cgroupfs icin little-endian 64-bit inode benzeri kimlik.
	var id uint64
	for i := 7; i >= 0; i-- {
		id = id<<8 | uint64(b[i])
	}
	return id, nil
}

var (
	// systemd surucusu:  .../kubepods-besteffort-pod<uid>.slice/cri-containerd-<id>.scope
	// cgroupfs surucusu: .../kubepods/besteffort/pod<uid>/<id>
	//
	// Iki UID bicimi var. Normal pod'lar cizgili UUID kullanir; statik (mirror)
	// pod'lar -- kube-apiserver, etcd, scheduler, controller-manager -- kubelet
	// tarafindan uretilen cizgisiz 32 haneli bir hash kullanir. Ikincisi
	// atlanirsa denetim duzlemi pod'lari akislara baglanamaz.
	rePodUID = regexp.MustCompile(
		`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}` +
			`|[0-9a-fA-F]{32})`)
	reContainer = regexp.MustCompile(`([0-9a-f]{64})`)
)

// Container, bir cgroup yolundan cikarilan Kubernetes kimlikleri.
type Container struct {
	PodUID      string // normalize edilmis (alt cizgi yerine tire)
	ContainerID string
}

// Parse, cgroup yolundan pod ve container kimligini cikarir. Ikisi de bos
// donebilir: yol bir Kubernetes is yuku olmayabilir (ornegin sistem servisi).
func Parse(path string) Container {
	var c Container
	if m := rePodUID.FindStringSubmatch(path); m != nil {
		c.PodUID = strings.ReplaceAll(m[1], "_", "-")
	}
	if m := reContainer.FindStringSubmatch(path); m != nil {
		c.ContainerID = m[1]
	}
	return c
}
