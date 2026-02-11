# calico-policy-visualiser Makefile
.ONESHELL:
.DEFAULT_GOAL := help

NPM ?= npm

.PHONY: help init dev test test-watch build lint preview clean print-config

help:
	@echo "Calico Network Policy Visualizer"
	@echo
	@echo "Available make targets:"
	@echo "  help            - Show this help message"
	@echo "  init            - Install node deps (first run)"
	@echo "  dev             - Start Vite dev server"
	@echo "  test            - Run tests (single run)"
	@echo "  test-watch      - Run tests in watch mode"
	@echo "  build           - Build production SPA into ./dist"
	@echo "  lint            - Run ESLint"
	@echo "  preview         - Preview the built SPA (vite preview)"
	@echo "  clean           - Remove node_modules and dist"
	@echo "  print-config    - Print effective paths/variables"

## Install node deps (first run)
init:
	$(NPM) install

## Start Vite dev server
dev:
	$(NPM) run dev

## Run tests (single run)
test:
	$(NPM) run test

## Run tests in watch mode
test-watch:
	$(NPM) run test:watch

## Build production SPA into ./dist
build:
	$(NPM) run build
	@echo "Built into ./dist"

## Run ESLint
lint:
	$(NPM) run lint

## Preview the built SPA (vite preview)
preview: build
	$(NPM) run preview

## Remove node_modules and dist
clean:
	rm -rf node_modules dist
	@echo "Cleaned node_modules and dist"

## Print effective paths/variables
print-config:
	@echo "NPM = $(NPM)"
