package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vtino17/devhibernate/internal/proc"
)

type Route struct {
	Target string `json:"target"`
	Owner  string `json:"owner"`
}

type Registry struct {
	Version int              `json:"version"`
	Routes  map[string]Route