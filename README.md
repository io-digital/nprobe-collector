# nprobe-collector

Nprobe Collector is a Go application (https://golang.org/) that analyses and aggregates TCP traffic according to its source and destination IP addresses using the NetFlow protocol (https://en.wikipedia.org/wiki/NetFlow). The objective is to see how bandwidth is used and then potentially treat certain locations differently in terms of pricing.

This repository contains 2 processors that are specific to our purposes, but can be used as examples of how to handle the incoming data. They show UDP and TCP implementations.
