package handlers

import (
	"net/http"
)

type GroupHandlers struct{}

func NewGroupHandlers() *GroupHandlers {
	return &GroupHandlers{}
}

func (h *GroupHandlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *GroupHandlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *GroupHandlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *GroupHandlers) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *GroupHandlers) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *GroupHandlers) RunGroup(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
