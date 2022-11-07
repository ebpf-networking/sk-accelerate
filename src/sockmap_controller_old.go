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
            // Do we need to implement anything here as data is usually static?
            /*
            deleteFromServicesMap(old.(*v1.Service))
            addToServicesMap(new.(*v1.Service))
            */
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
            // This call usually returns as endpoint.Subsets is usually empty at this time
            addToEndpointsMap(endpoint)
        },
        UpdateFunc: func(old, new interface{}) {
            oldEndpoint := old.(*v1.Endpoints)
            newEndpoint := new.(*v1.Endpoints)
            if (len(oldEndpoint.Subsets) != len(newEndpoint.Subsets)) {
                o := old.(*v1.Endpoints)
                for i, e := range *endpoints {
                if ((o.ObjectMeta.Namespace == e.ObjectMeta.Namespace) && 
                    (o.ObjectMeta.Name == e.ObjectMeta.Name)) {
                    (*endpoints)[i] = (*endpoints)[len(*endpoints)-1]
                    *endpoints = (*endpoints)[:len(*endpoints)-1]
                    break
                }
                }
                deleteFromEndpointsMap(o)

                n := new.(*v1.Endpoints)
                *endpoints = append(*endpoints, n)
                addToEndpointsMap(n)
            }
        },
        DeleteFunc: func(obj interface{}) {
            // This is not very useful as endpoint.Subsets is empty at this point
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
            deleteFromEndpointsMap(endpoint)
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
        fmt.Printf("adding service to services_map: %s -> %s\n", key, value)
    } else {
        fmt.Printf("service is already in services_map: %s\n", key)
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
        fmt.Printf("service does not exist in services_map: %s\n", key)
    } else {
        fmt.Printf("service is deleted from services_map: %s\n", key)
    }
}

func addToEndpointsMap(endpoint *v1.Endpoints) {
    path := filepath.Join("/sys/fs/bpf", "endpoints_ips_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    path = filepath.Join("/sys/fs/bpf", "endpoints_ports_map")
    n, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer n.Close()

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], endpoint.ObjectMeta.Namespace)
    copy(name[:], endpoint.ObjectMeta.Name)

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return;
    }

    // Populate endpoints_ips_map
    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        var value uint32
        outer_key := endpoint_outer_key{Namespace: namespace, Name: name}
        err = m.Lookup(outer_key, &value)
        if errors.Is(err, ebpf.ErrKeyNotExist) {
            // Handling new endpoints to a new service
            fmt.Printf("adding a new service to endpoints_ips_map: %s:%s\n", namespace, name)
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

            fd := uint32(h.FD())
            err = m.Put(outer_key, fd)
            if (err != nil) {
                panic(err)
            }
        } else {
            fmt.Printf("service already exists in endpoints_ips_map: %s:%s\n", namespace, name)
        }

        if (value <= 0) {
            err = m.Lookup(outer_key, &value)
            if errors.Is(err, ebpf.ErrKeyNotExist) {
                panic("expect to find the key in endpoints_ips_map but didn't")
            }
        }

        h, err := ebpf.NewMapFromID(ebpf.MapID(value))
        if (err != nil) {
            panic("expect to find inner map from endpoints_ips_map but didn't")
        }
        defer h.Close()

        for _, address := range addresses {
            ip := net.ParseIP(address.IP)
            fmt.Printf("adding a new endpoint IP address to endpoints_ips_map: %s:%s -> %s\n", namespace, name, ip) 

            inner_key := ip.To16()
            inner_value := uint32(0)
            err = h.Put(inner_key, inner_value)
            if (err != nil) {
                panic(err)
            }
        }
    }

    // Populate endpoints_ports_map
    for _, subset := range subsets {
        ports := subset.Ports
        if (ports == nil) {
            continue
        }

        var value uint32
        outer_key := endpoint_outer_key{Namespace: namespace, Name: name}
        err = n.Lookup(outer_key, &value)
        if errors.Is(err, ebpf.ErrKeyNotExist) {
            // Handling new endpoints to a new service
            fmt.Printf("adding a new service to endpoints_ports_map: %s:%s\n", namespace, name)
            h, err := ebpf.NewMap(&ebpf.MapSpec{
                Type:       ebpf.Hash,
                KeySize:    4,
                ValueSize:  4,
                MaxEntries: 128,
            })
            defer h.Close()
            if (err != nil) {
                panic(err)
            }

            fd := uint32(h.FD())
            err = n.Put(outer_key, fd)
            if (err != nil) {
                panic(err)
            }
        } else {
            fmt.Printf("service already exists in endpoints_ports_map: %s:%s\n", namespace, name)
        }

        if (value <= 0) {
            err = n.Lookup(outer_key, &value)
            if errors.Is(err, ebpf.ErrKeyNotExist) {
                panic("expect to find the key in endpoints_ports_map but didn't")
            }
        }

        h, err := ebpf.NewMapFromID(ebpf.MapID(value))
        if (err != nil) {
            panic("expect to find inner map from endpoints_ports_map but didn't")
        }
        defer h.Close()

        for _, port := range ports {
            // We only handle TCP and TCP is default is Protocol field is not specified
            if (port.Protocol != "" && port.Protocol != "TCP") {
                continue
            }
            portNum := port.Port
            fmt.Printf("adding a new endpoint port to endpoints_ports_map: %s:%s -> %d\n", namespace, name, portNum)

            inner_key := portNum
            inner_value := uint32(0)
            err = h.Put(inner_key, inner_value)
            if (err != nil) {
                panic(err)
            }
        }
    }
}

func deleteFromEndpointsMap(endpoint *v1.Endpoints) {

    path := filepath.Join("/sys/fs/bpf", "endpoints_ips_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    path = filepath.Join("/sys/fs/bpf", "endpoints_ports_map")
    n, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer n.Close()

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], endpoint.ObjectMeta.Namespace)
    copy(name[:], endpoint.ObjectMeta.Name)

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return;
    }

    // Delete from endpoints_ips_map
    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        var value uint32
        outer_key := endpoint_outer_key{Namespace: namespace, Name: name}
        err = m.Lookup(outer_key, &value)
        if errors.Is(err, ebpf.ErrKeyNotExist) {
            continue
        }

        h, err := ebpf.NewMapFromID(ebpf.MapID(value))
        if (err != nil) {
            panic("expect to find inner map from endpoints_ips_map but didn't")
        }
        defer h.Close()

        for _, address := range addresses {
            ip := net.ParseIP(address.IP)
            fmt.Printf("deleting an endpoint IP address from endpoints_ips_map: %s:%s -> %s\n", namespace, name, ip) 

            inner_key := ip.To16()
            err = h.Delete(inner_key)
            if (err != nil) {
                panic(err)
            }
        }

        b, err := h.NextKeyBytes(nil)
        if (err != nil) {
            panic(err)
        }
        if (b == nil) {
            err = m.Delete(outer_key)
            if (err != nil) {
                panic(err)
            }
        }
    }

    // Delete from endpoints_port_map
    for _, subset := range subsets {
        ports := subset.Ports
        if (ports == nil) {
            continue
        }

        var value uint32
        outer_key := endpoint_outer_key{Namespace: namespace, Name: name}
        err = n.Lookup(outer_key, &value)
        if errors.Is(err, ebpf.ErrKeyNotExist) {
            continue
        }

        h, err := ebpf.NewMapFromID(ebpf.MapID(value))
        if (err != nil) {
            panic("expect to find inner map from endpoints_ports_map but didn't")
        }
        defer h.Close()

        for _, port := range ports {
            // We only handle TCP and TCP is default is Protocol field is not specified
            if (port.Protocol != "" && port.Protocol != "TCP") {
                continue
            }

            portNum := port.Port
            fmt.Printf("deleting an endpoint port from endpoints_ports_map: %s:%s -> %d\n", namespace, name, portNum)

            inner_key := portNum
            err = h.Delete(inner_key)
            if (err != nil) {
                panic(err)
            }
        }

        b, err := h.NextKeyBytes(nil)
        if (err != nil) {
            panic(err)
        }
        if (b == nil) {
            err = n.Delete(outer_key)
            if (err != nil) {
                panic(err)
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
    //go printStats(&services, &endpoints)

    for {
        time.Sleep(time.Duration(1<<63 - 1))
    }
}