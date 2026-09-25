// resolver_test.go — cgroup yolu ayristirmayi kilitler.
//
// # NEDEN BU TEST VAR
//
// Pod UID ve container ID, cgroup yolundan duzenli ifadeyle cikariliyor ve
// yolun bicimi calisma ortamina gore DEGISIYOR:
//
//	systemd surucusu   .../kubepods-besteffort-pod<uuid>.slice/cri-...scope
//	cgroupfs surucusu  .../kubepods/besteffort/pod<uuid>/<id>
//
// Ustelik iki farkli UID bicimi var: normal pod'lar cizgili UUID kullanir,
// statik (mirror) pod'lar -- kube-apiserver, etcd, scheduler -- kubelet'in
// urettigi cizgisiz 32 haneli bir hash. Ikincisi bir kez atlandi ve denetim
// duzlemi pod'lari akislara baglanamadi; bu test o regresyonun tekrarini
// engelliyor.
//
// Kubernetes'e ait OLMAYAN yollar (sistem servisleri, kullanici oturumlari)
// da test ediliyor: bos alan donmeli, yanlis eslesme degil.
package cgroups

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		wantPod  string
		wantCont string
	}{
		{
			name:     "systemd surucusu",
			path:     "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod2c223d78_1c81_49f5_8269_44550bf786a9.slice/cri-containerd-fb1aaaeeb2f29e7148886f8a4cd675aad1da176b3635a93b92269f88c11eed43.scope",
			wantPod:  "2c223d78-1c81-49f5-8269-44550bf786a9",
			wantCont: "fb1aaaeeb2f29e7148886f8a4cd675aad1da176b3635a93b92269f88c11eed43",
		},
		{
			name:     "cgroupfs surucusu",
			path:     "/kubepods/besteffort/pod298365fd-2741-4f1f-8006-79bb16d1b8b6/754b4d6af0d956b1ae4ce13630c1a87ecb0459d988d7db78a7ddc1d4248be5ef",
			wantPod:  "298365fd-2741-4f1f-8006-79bb16d1b8b6",
			wantCont: "754b4d6af0d956b1ae4ce13630c1a87ecb0459d988d7db78a7ddc1d4248be5ef",
		},
		{
			// Statik pod: kubelet cizgisiz 32 haneli hash uretiyor.
			name:     "statik pod",
			path:     "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod31de2a22db2b6dcc5c598cb59fab2552.slice/cri-containerd-3c7f1b3e0112df5f33d3281027e5a931c1ccb4fc638ed4f7b0948c669a821156.scope",
			wantPod:  "31de2a22db2b6dcc5c598cb59fab2552",
			wantCont: "3c7f1b3e0112df5f33d3281027e5a931c1ccb4fc638ed4f7b0948c669a821156",
		},
		{
			name: "kubernetes disi",
			path: "/system.slice/kubelet.service",
		},
		{
			name: "kullanici oturumu",
			path: "/user.slice/user-1000.slice/session-4.scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.path)
			if got.PodUID != tc.wantPod {
				t.Errorf("PodUID = %q, beklenen %q", got.PodUID, tc.wantPod)
			}
			if got.ContainerID != tc.wantCont {
				t.Errorf("ContainerID = %q, beklenen %q", got.ContainerID, tc.wantCont)
			}
		})
	}
}
