package main

import (
    "fmt"
    "flag"
    "time"
    "path/filepath"

    "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/util/wait"
    "k8s.io/apimachinery/pkg/labels"
    "k8s.io/client-go/informers"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/util/homedir"
    "k8s.io/client-go/rest"
)

func monitorServices(informerFactory informers.SharedInformerFactory, services *[]*v1.Service) {

    serviceInformer := informerFactory.Core().V1().Services()
    serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
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
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
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
        fmt.Println("Services:")
        for i, service := range *services {
            fmt.Printf("\t[%d]: ", i)
            fmt.Println(service)
        }

        fmt.Println("Endpoints:")
        for i, endpoint := range *endpoints {
            fmt.Printf("\t[%d]: ", i)
            fmt.Println(endpoint)
        }
        time.Sleep(5*time.Second)

    }
}

func main() {
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
