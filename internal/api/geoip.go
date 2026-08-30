package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/geoip"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/gin-gonic/gin"
)

// handleGeoIP resolves a host (?host=) to a country code + flag, so the inbound
// form's "Detect" button can auto-fill the country for the {FLAG}/{COUNTRY}
// naming tokens. With no host it geolocates the panel's own address. A failure
// is reported plainly — the operator keeps the manual field.
func (s *Server) handleGeoIP(c *gin.Context) {
	host := strings.TrimSpace(c.Query("host"))
	if host == "" {
		host = hostOnly(c.Request.Host) // detect the panel's own country
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	cc, err := geoip.LookupCountry(ctx, host)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "geoip-lookup", Kind: apierr.KindNetwork,
			Message: "country lookup failed: " + err.Error(), Cause: err,
			Remediation: "the panel host may be unable to reach a geoip service; type the 2-letter code manually."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"country_code": cc, "flag": model.CountryFlag(cc), "host": host})
}
