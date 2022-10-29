package main

import (
    "fmt"
    "flag"
    "time"
    "path/filepath"
    "net"
    "errors"

    "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/util/wait"
    "k8s.io/apimachinery/pkg/labels"
    "k8s.io/client-go/informers"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/util/homedir"
    "k8s.io/client-go/rest"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

type service_key struct {
    IP [16]byte
}

type service_value struct {
    Namespace [128]byte
    Name [128]byte
}

type endpoint_outer_key struct {
    Namespace [128]byte
    Name [128]byte
}

type endpoint_inner_key struct {
    IP [16]byte
}

func monitorServices(informerFactory informers.SharedInformerFactory, services *[]*v1.Service) {

    serviceInformer := informerFactory.Core().V1().Services()
    serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
            //fmt.Println("*** Add service ***:")
            //fmt.Printf("\t[+]: ")
            service := new.(*v1.Service)
            //fmt.Println(service)
            *services = append(*services, service)
            addToServicesMap(service)
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
            //fmt.Println("*** Delete service ***:")
            //fmt.Printf("\t[-]: ")
            service := obj.(*v1.Service)
            //fmt.Println(service)
            for i, s := range *services {
                if ((service.ObjectMeta.Namespace == s.ObjectMeta.Namespace) && 
                    (service.ObjectMeta.Name == s.ObjectMeta.Name)) {
                    (*services)[i] = (*services)[len(*services)-1]
                    *services = (*services)[:len(*services)-1]
                    deleteFromServicesMap(service)
                    break
                }
            }
        },
    })

    informerFactory.Start(wait.NeverStop)
    informerFactory.WaitForCacheSync(wait.NeverStop)

    // List service endpoints in all namespaces in the cluster
    var err error
    *services, err = serviceInformer.Lister().Services("").List(labels.Everything())
    if (err != nil) {
        panic(err.Error())
    }
}

func monitorEndpoints(informerFactory informers.SharedInformerFactory, endpoints *[]*v1.Endpoints) {

    endpointInformer := informerFactory.Core().V1().Endpoints()
    endpointInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
            //fmt.Println("*** Add endpoints ***:")
            //fmt.Printf("\t[+]: ")
            endpoint := new.(*v1.Endpoints)
            //fmt.Println(endpoint)
            *endpoints = append(*endpoints, endpoint)
            addToEndpointsMap(endpoint)
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
            //fmt.Println("*** Delete endpoints: ***")
            //fmt.Printf("\t[-]: ")
            endpoint := obj.(*v1.Endpoints)
            //fmt.Println(endpoint)
            for i, e := range *endpoints {
                if ((endpoint.ObjectMeta.Namespace == e.ObjectMeta.Namespace) && 
                    (endpoint.ObjectMeta.Name == e.ObjectMeta.Name)) {
                    (*endpoints)[i] = (*endpoints)[len(*endpoints)-1]
                    *endpoints = (*endpoints)[:len(*endpoints)-1]
                    break
                }
            }
        },
    })

    informerFactory.Start(wait.NeverStop)
    informerFactory.WaitForCacheSync(wait.NeverStop)

    // List service endpoints in all namespaces in the cluster
    var err error
    *endpoints, err = endpointInformer.Lister().Endpoints("").List(labels.Everything())
    if (err != nil) {
        panic(err.Error())
    }
}

func printStats(services *[]*v1.Service, endpoints *[]*v1.Endpoints) {

    for {
        fmt.Println("*** Services ***:")
        for i, service := range *services {
            fmt.Printf("\t[%d]: ", i)
            fmt.Println(service)
        }

        fmt.Println("*** Endpoints ***:")
        for i, endpoint := range *endpoints {
            fmt.Printf("\t[%d]: ", i)
            fmt.Println(endpoint)
        }
        time.Sleep(5*time.Second)
    }
}

// Todo: services map could be opened once at the start and
// passed as a parameter to these functions
func addToServicesMap(service *v1.Service) {
    path := filepath.Join("/sys/fs/bpf", "services_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], service.ObjectMeta.Namespace)
    copy(name[:], service.ObjectMeta.Name)
    ip := net.ParseIP(service.Spec.ClusterIP)
    if (ip == nil) {
        panic("Cannot find or parse service IP")
    }

    key := ip.To16()
    var value service_value
    err = m.Lookup(key, &value)
    if errors.Is(err, ebpf.ErrKeyNotExist) {
        value = service_value{Namespace: namespace, Name: name}
        err = m.Put(key, value)
        if (err != nil) {
            panic(err.Error())
        }
        fmt.Printf("adding service to eBPF map: %s -> %s\n", key, value)
    } else {
        fmt.Printf("service is already in eBPF map: %s\n", key)
    }
}

func deleteFromServicesMap(service *v1.Service) {
    path := filepath.Join("/sys/fs/bpf", "services_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], service.ObjectMeta.Namespace)
    copy(name[:], service.ObjectMeta.Name)
    ip := net.ParseIP(service.Spec.ClusterIP)
    if (ip == nil) {
        panic("Cannot find or parse service IP")
    }

    key := ip.To16()
    err = m.Delete(key)
    if errors.Is(err, ebpf.ErrKeyNotExist) {
        fmt.Printf("service does not exist in eBPF map: %s\n", key)
    } else {
        fmt.Printf("service is deleted from eBPF map: %s\n", key)
    }
}

func addToEndpointsMap(endpoint *v1.Endpoints) {
    path := filepath.Join("/sys/fs/bpf", "endpoints_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], endpoint.ObjectMeta.Namespace)
    copy(name[:], endpoint.ObjectMeta.Name)

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return;
    }

    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        var value uint32
        for _, address := range addresses {
            ip := net.ParseIP(address.IP)
            fmt.Printf("%s:%s -> %s\n", namespace, name, ip) 

            outer_key := endpoint_outer_key{Namespace: namespace, Name: name}
            err = m.Lookup(outer_key, &value)
            if errors.Is(err, ebpf.ErrKeyNotExist) {
                h, err := ebpf.NewMap(&ebpf.MapSpec{
                    Type:       ebpf.Hash,
                    KeySize:    16,
                    ValueSize:  4,
                    MaxEntries: 128,
                })
                defer h.Close()
                if (err != nil) {
                    panic(err)
                }

                inner_key := ip.To16()
                inner_value := uint32(0)
                err = h.Put(inner_key, inner_value)
                if (err != nil) {
                    panic(err)
                }
                fd := uint32(h.FD())
                err = m.Put(outer_key, fd)
                if (err != nil) {
                    panic(err)
                }

                fmt.Println("key not found")
            } else {
                fmt.Println("key was found")
            }
        }
    }
}

func main() {
    rlimit.RemoveMemlock()
    var kubeconfig *string
    if home := homedir.HomeDir(); home != "" {
        kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
    } else {
        kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
    }
    flag.Parse()

    config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
    if err != nil {
        config, err = rest.InClusterConfig()
        if err != nil {
            panic(err.Error())
        }
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        panic(err.Error())
    }

    informerFactory := informers.NewSharedInformerFactory(clientset, 10*time.Second)

    var services []*v1.Service
    var endpoints []*v1.Endpoints

    go monitorServices(informerFactory, &services)
    go monitorEndpoints(informerFactory, &endpoints)
    go printStats(&services, &endpoints)

    for {
        time.Sleep(time.Duration(1<<63 - 1))
    }
}
