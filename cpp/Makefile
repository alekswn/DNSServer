# Makefile for DNS Server

CXX = g++
CXXFLAGS = -std=c++11 -Wall -g

all: dns_server

dns_server: src/dns_server.cpp
	$(CXX) $(CXXFLAGS) -o dns_server src/dns_server.cpp

clean:
	rm -f dns_server
