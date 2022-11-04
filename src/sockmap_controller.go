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
    //"k8s.io/apimachinery/pkg/labels"
    "k8s.io/client-go/informers"
    client_go_v1 "k8s.io/client-go/informers/core/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/util/homedir"
    "k8s.io/client-go/rest"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

type map_key struct {
    IP net.IP
    Pad uint32
    Port int32
}

type map_value struct {
    IP net.IP
    Pad uint32
    Port int32
}

func monitorEndpoints(informerFactory informers.SharedInformerFactory, endpoints map[string]*v1.Endpoints) {

    // Starts serviceInformer so we can query services more efficiently
    serviceInformer := informerFactory.Core().V1().Services()
    serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
        },
    })

    // Starts endpointInformer so we can handle endpoint events
    endpointInformer := informerFactory.Core().V1().Endpoints()
    endpointInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
            fmt.Println("Addfunc")
            endpoint := new.(*v1.Endpoints)
            namespace := endpoint.ObjectMeta.Namespace
            name := endpoint.ObjectMeta.Name
            key := namespace + ":" + name
            if _, ok := endpoints[key]; ok {
                // This endpoint already exists
                fmt.Printf("Adding an endpoint %s that already exists\n", key)
                return
            }
            endpoints[key] = endpoint
            // This call usually returns as endpoint.Subsets is usually empty at this time
            addEndpointToMap(endpoint, serviceInformer)
        },
        UpdateFunc: func(old, new interface{}) {
            fmt.Println("Updatefunc")
            o := old.(*v1.Endpoints)
            n := new.(*v1.Endpoints)
            if ((len(o.Subsets) != len(n.Subsets)) && 
                (o.ObjectMeta.Namespace == n.ObjectMeta.Namespace) &&
                (o.ObjectMeta.Name == n.ObjectMeta.Name)) {
                key := o.ObjectMeta.Namespace + ":" + o.ObjectMeta.Name
                endpoints[key] = n
                deleteEndpointFromMap(o)
                addEndpointToMap(n, serviceInformer)
            }
        },
        DeleteFunc: func(obj interface{}) {
            fmt.Println("Deletefunc")
            // This is not very useful as endpoint.Subsets is empty at this point
            endpoint := obj.(*v1.Endpoints)
            namespace := endpoint.ObjectMeta.Namespace
            name := endpoint.ObjectMeta.Name
            key := namespace + ":" + name
            delete(endpoints, key)
            deleteEndpointFromMap(endpoint)
        },
    })

    informerFactory.Start(wait.NeverStop)
    informerFactory.WaitForCacheSync(wait.NeverStop)
}

func addEndpointToMap(endpoint *v1.Endpoints, serviceInformer client_go_v1.ServiceInformer) {
    service, err := serviceInformer.Lister().Services(endpoint.ObjectMeta.Namespace).Get(endpoint.ObjectMeta.Name)
    if (err != nil) {
        return
    }

    servicePorts := service.Spec.Ports
    if (len(servicePorts) == 0) {
        return
    }

    serviceIP := net.ParseIP(service.Spec.ClusterIP)
    if (serviceIP == nil) {
        return
    }

    var namespace [128]byte
    var name [128]byte
    copy(namespace[:], endpoint.ObjectMeta.Namespace)
    copy(name[:], endpoint.ObjectMeta.Name)

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return
    }

    path := filepath.Join("/sys/fs/bpf", "endpoints_to_service_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    // Populate endpoints_to_service_map
    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        for _, address := range addresses {
            podIP := net.ParseIP(address.IP)
            
            for _, port := range servicePorts {
                // We only handle TCP and TCP is default if the Protocol field is not specified
                if (port.Protocol != "" && port.Protocol != "TCP") {
                    continue
                }

                servicePort := port.Port
                // TODO: TargetPort could be an name, for now we assume it is a number
                podPort := int32(port.TargetPort.IntValue())

                key := map_key{IP: podIP.To16(), Pad: 0, Port: podPort}
                var value map_value;
                err := m.Lookup(key, &value)
                if errors.Is(err, ebpf.ErrKeyNotExist) {
                    value := map_value{IP: serviceIP.To16(), Pad: 0, Port: servicePort}
                    err = m.Put(key, value)
                    if (err != nil) {
                        panic(err.Error())
                    }
                    fmt.Printf("(+) %s -> %s\n", key, value)
                } else {
                    fmt.Printf("(.) key already exists: %s\n", key)
                }
            }
        }
    }
    return
}

func deleteEndpointFromMap(endpoint *v1.Endpoints) {
    return
}

func printEndpoints(endpoints map[string]*v1.Endpoints) {
    for {
        for key, value:= range endpoints {
            fmt.Printf("%s: %s\n", key, value)
        }
        time.Sleep(5*time.Second)
    }
}

func main() {
    rlimit.RemoveMemlock()
    var kubeconfig *string
    if home := homedir.HomeDir(); home != "" {
        kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
    } else {
        kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file") }
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

    endpoints := make(map[string]*v1.Endpoints)
    go monitorEndpoints(informerFactory, endpoints)
    go printEndpoints(endpoints)

    for {
        time.Sleep(time.Duration(1<<63 - 1))
    }
}
