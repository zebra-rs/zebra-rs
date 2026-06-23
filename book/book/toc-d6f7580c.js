// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-00-introduction.html">zebra-rs Routing Software</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-01-router-id.html"><strong aria-hidden="true">1.</strong> Router ID Selection</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-02-interface-configuration.html"><strong aria-hidden="true">2.</strong> Interface Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-03-vxlan-configuration.html"><strong aria-hidden="true">3.</strong> VXLAN Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-04-bridge-configuration.html"><strong aria-hidden="true">4.</strong> Bridge Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-00-05-command-line-options.html"><strong aria-hidden="true">5.</strong> Command Line Options</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-01-00-what-is-static-route.html"><strong aria-hidden="true">6.</strong> Static Route</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-01-01-floating-static-route.html"><strong aria-hidden="true">6.1.</strong> Floating Static Route</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-01-02-recursive-static-route.html"><strong aria-hidden="true">6.2.</strong> Recursive Static Route</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-00-what-is-bgp.html"><strong aria-hidden="true">7.</strong> BGP</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-26-bgp-neighbor-group.html"><strong aria-hidden="true">7.1.</strong> Neighbor Groups</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-01-dynamic-neighbors.html"><strong aria-hidden="true">7.2.</strong> Dynamic Neighbors</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-27-bgp-unnumbered.html"><strong aria-hidden="true">7.3.</strong> IPv6 Unnumbered (interface-neighbor)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-02-tcp-authentication.html"><strong aria-hidden="true">7.4.</strong> Session Authentication (TCP MD5 / TCP-AO)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-11-bgp-ttl-security.html"><strong aria-hidden="true">7.5.</strong> TTL: eBGP Multihop &amp; Security (GTSM)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-14-bgp-tcp-mss.html"><strong aria-hidden="true">7.6.</strong> TCP MSS</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-23-bgp-port.html"><strong aria-hidden="true">7.7.</strong> TCP Port (listen &amp; per-neighbor)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-12-bgp-as-override.html"><strong aria-hidden="true">7.8.</strong> AS Override</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-30-bgp-local-as.html"><strong aria-hidden="true">7.9.</strong> Local AS (AS Migration)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-13-bgp-allowas-in.html"><strong aria-hidden="true">7.10.</strong> allowas-in (Inbound AS_PATH Loop Relaxation)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-14-bgp-remove-private-as.html"><strong aria-hidden="true">7.11.</strong> Remove Private AS</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-15-bgp-enforce-first-as.html"><strong aria-hidden="true">7.12.</strong> Enforce First AS</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-24-bgp-well-known-communities.html"><strong aria-hidden="true">7.13.</strong> Well-Known Communities</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-28-bgp-table-map.html"><strong aria-hidden="true">7.14.</strong> Table-Map (Policy at the BGP→RIB Install Point)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-16-bgp-disable-connected-check.html"><strong aria-hidden="true">7.15.</strong> disable-connected-check</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-29-bgp-ip-transparent.html"><strong aria-hidden="true">7.16.</strong> ip-transparent (non-local update-source)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-17-bgp-srv6-encapsulation-type.html"><strong aria-hidden="true">7.17.</strong> SRv6 Encapsulation Type (per-neighbor)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-03-bgp-timers.html"><strong aria-hidden="true">7.18.</strong> Timer Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-04-bgp-l3vpn.html"><strong aria-hidden="true">7.19.</strong> L3VPN and Per-VRF Labels</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-05-bgp-l3vpn-srv6.html"><strong aria-hidden="true">7.20.</strong> L3VPN over an SRv6 Underlay</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-06-bgp-evpn-type5.html"><strong aria-hidden="true">7.21.</strong> EVPN Type-5 (IP Prefix Routes)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-32-bgp-evpn-igmp-mld-proxy.html"><strong aria-hidden="true">7.22.</strong> EVPN IGMP/MLD Proxy (Selective Multicast)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-33-bgp-evpn-assisted-replication.html"><strong aria-hidden="true">7.23.</strong> EVPN BUM &amp; Assisted Replication</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-34-bgp-evpn-segmentation.html"><strong aria-hidden="true">7.24.</strong> EVPN BUM Tunnel Segmentation (RFC 9572)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-35-bgp-mup.html"><strong aria-hidden="true">7.25.</strong> Mobile User Plane (MUP) &amp; the MUP Controller</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-07-bgp-rtc.html"><strong aria-hidden="true">7.26.</strong> Route Target Constraint (RTC)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-18-bgp-interas.html"><strong aria-hidden="true">7.27.</strong> Inter-AS L3VPN</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-20-bgp-interas-option-a.html"><strong aria-hidden="true">7.27.1.</strong> Option A (back-to-back VRFs)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-21-bgp-interas-option-b.html"><strong aria-hidden="true">7.27.2.</strong> Option B (VPNv4 between ASBRs)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-19-bgp-interas-option-c.html"><strong aria-hidden="true">7.27.3.</strong> Option C over SR-MPLS</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-22-bgp-interas-option-ab.html"><strong aria-hidden="true">7.27.4.</strong> Option AB (hybrid)</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-08-bgp-bfd.html"><strong aria-hidden="true">7.28.</strong> BFD</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-09-bgp-route-reflector.html"><strong aria-hidden="true">7.29.</strong> Route Reflector</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-31-bgp-rib-sharding.html"><strong aria-hidden="true">7.30.</strong> RIB Sharding (Parallel Route Processing)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-25-bgp-clear.html"><strong aria-hidden="true">7.31.</strong> Clearing BGP Sessions</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-02-10-bgp-tracing.html"><strong aria-hidden="true">7.32.</strong> Conditional Tracing</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-00-isis.html"><strong aria-hidden="true">8.</strong> IS-IS</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-01-isis-timers.html"><strong aria-hidden="true">8.1.</strong> Timer Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-02-isis-srlg.html"><strong aria-hidden="true">8.2.</strong> Shared Risk Link Group (SRLG)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-03-isis-bfd.html"><strong aria-hidden="true">8.3.</strong> BFD</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-04-isis-clear.html"><strong aria-hidden="true">8.4.</strong> Clearing IS-IS State</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-05-isis-lsp-mtu.html"><strong aria-hidden="true">8.5.</strong> LSP MTU and Fragmentation</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-06-isis-redistribution.html"><strong aria-hidden="true">8.6.</strong> Route Redistribution</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-07-isis-passive.html"><strong aria-hidden="true">8.7.</strong> Passive Interfaces</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-07-08-isis-egress-protection.html"><strong aria-hidden="true">8.8.</strong> Egress Protection (Mirror SID)</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-08-00-ospf.html"><strong aria-hidden="true">9.</strong> OSPF</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-08-01-ospf-configuration.html"><strong aria-hidden="true">9.1.</strong> Configuration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-08-02-ospf-bfd.html"><strong aria-hidden="true">9.2.</strong> BFD</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-08-03-ospf-clear.html"><strong aria-hidden="true">9.3.</strong> Clearing OSPF State</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-10-00-bfd.html"><strong aria-hidden="true">10.</strong> BFD</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-10-01-bfd-xdp-helper.html"><strong aria-hidden="true">10.1.</strong> The XDP/eBPF Data-Plane Helper</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-12-00-nexthop-protect.html"><strong aria-hidden="true">11.</strong> Fast Failover: TI-LFA + BFD (NexthopProtect)</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-09-00-twamp-stamp.html"><strong aria-hidden="true">12.</strong> STAMP</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-04-00-srv6.html"><strong aria-hidden="true">13.</strong> SRv6</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-05-00-policy.html"><strong aria-hidden="true">14.</strong> Policy</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-05-01-policy-control-flow.html"><strong aria-hidden="true">14.1.</strong> Control Flow</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-05-02-policy-match.html"><strong aria-hidden="true">14.2.</strong> Match</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-05-03-policy-set.html"><strong aria-hidden="true">14.3.</strong> Set</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-05-04-lua-scripting.html"><strong aria-hidden="true">14.4.</strong> Lua Scripting</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-06-00-vty-access.html"><strong aria-hidden="true">15.</strong> VTY Access and Authentication</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-06-01-session-design.html"><strong aria-hidden="true">15.1.</strong> Session Management Design</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-06-02-show-config-commands.html"><strong aria-hidden="true">15.2.</strong> Show Config Commands</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-13-00-mcp-server.html"><strong aria-hidden="true">16.</strong> Native MCP Server</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-00-logging-overview.html"><strong aria-hidden="true">17.</strong> Logging Configuration</a><a class="chapter-fold-toggle"><div>❱</div></a></span><ol class="section"><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-01-log-output-destinations.html"><strong aria-hidden="true">17.1.</strong> Log Output Destinations</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-02-log-formats.html"><strong aria-hidden="true">17.2.</strong> Log Formats</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-03-protocol-logging.html"><strong aria-hidden="true">17.3.</strong> Protocol-Specific Logging</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-06-rib-fib-tracing.html"><strong aria-hidden="true">17.4.</strong> RIB/FIB Tracing</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-04-logging-integration.html"><strong aria-hidden="true">17.5.</strong> Logging Integration</a></span></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-03-05-logging-troubleshooting.html"><strong aria-hidden="true">17.6.</strong> Logging Troubleshooting</a></span></li></ol><li class="chapter-item "><span class="chapter-link-wrapper"><a href="ch-11-00-bdd-tests.html"><strong aria-hidden="true">18.</strong> BDD Integration Tests</a></span></li><li class="chapter-item "><li class="spacer"></li></li><li class="chapter-item "><li class="part-title">Appendices</li></li><li class="chapter-item "><span class="chapter-link-wrapper"><a href="appendix-a-logging-quick-reference.html"><strong aria-hidden="true">19.</strong> Appendix A: Logging Quick Reference</a></span></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split('#')[0].split('?')[0];
        if (current_page.endsWith('/')) {
            current_page += 'index.html';
        }
        const links = Array.prototype.slice.call(this.querySelectorAll('a'));
        const l = links.length;
        for (let i = 0; i < l; ++i) {
            const link = links[i];
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The 'index' page is supposed to alias the first chapter in the book.
            // Check both with and without the '.html' suffix to be robust against pretty URLs
            if (link.href.replace(/\.html$/, '') === current_page.replace(/\.html$/, '')
                || i === 0
                && path_to_root === ''
                && current_page.endsWith('/index.html')) {
                link.classList.add('active');
                let parent = link.parentElement;
                while (parent) {
                    if (parent.tagName === 'LI' && parent.classList.contains('chapter-item')) {
                        parent.classList.add('expanded');
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', e => {
            if (e.target.tagName === 'A') {
                const clientRect = e.target.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                sessionStorage.setItem('sidebar-scroll-offset', clientRect.top - sidebarRect.top);
            }
        }, { passive: true });
        const sidebarScrollOffset = sessionStorage.getItem('sidebar-scroll-offset');
        sessionStorage.removeItem('sidebar-scroll-offset');
        if (sidebarScrollOffset !== null) {
            // preserve sidebar scroll position when navigating via links within sidebar
            const activeSection = this.querySelector('.active');
            if (activeSection) {
                const clientRect = activeSection.getBoundingClientRect();
                const sidebarRect = this.getBoundingClientRect();
                const currentOffset = clientRect.top - sidebarRect.top;
                this.scrollTop += currentOffset - parseFloat(sidebarScrollOffset);
            }
        } else {
            // scroll sidebar to current active section when navigating via
            // 'next/previous chapter' buttons
            const activeSection = document.querySelector('#mdbook-sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        const sidebarAnchorToggles = document.querySelectorAll('.chapter-fold-toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(el => {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define('mdbook-sidebar-scrollbox', MDBookSidebarScrollbox);


// ---------------------------------------------------------------------------
// Support for dynamically adding headers to the sidebar.

(function() {
    // This is used to detect which direction the page has scrolled since the
    // last scroll event.
    let lastKnownScrollPosition = 0;
    // This is the threshold in px from the top of the screen where it will
    // consider a header the "current" header when scrolling down.
    const defaultDownThreshold = 150;
    // Same as defaultDownThreshold, except when scrolling up.
    const defaultUpThreshold = 300;
    // The threshold is a virtual horizontal line on the screen where it
    // considers the "current" header to be above the line. The threshold is
    // modified dynamically to handle headers that are near the bottom of the
    // screen, and to slightly offset the behavior when scrolling up vs down.
    let threshold = defaultDownThreshold;
    // This is used to disable updates while scrolling. This is needed when
    // clicking the header in the sidebar, which triggers a scroll event. It
    // is somewhat finicky to detect when the scroll has finished, so this
    // uses a relatively dumb system of disabling scroll updates for a short
    // time after the click.
    let disableScroll = false;
    // Array of header elements on the page.
    let headers;
    // Array of li elements that are initially collapsed headers in the sidebar.
    // I'm not sure why eslint seems to have a false positive here.
    // eslint-disable-next-line prefer-const
    let headerToggles = [];
    // This is a debugging tool for the threshold which you can enable in the console.
    let thresholdDebug = false;

    // Updates the threshold based on the scroll position.
    function updateThreshold() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;

        // The number of pixels below the viewport, at most documentHeight.
        // This is used to push the threshold down to the bottom of the page
        // as the user scrolls towards the bottom.
        const pixelsBelow = Math.max(0, documentHeight - (scrollTop + windowHeight));
        // The number of pixels above the viewport, at least defaultDownThreshold.
        // Similar to pixelsBelow, this is used to push the threshold back towards
        // the top when reaching the top of the page.
        const pixelsAbove = Math.max(0, defaultDownThreshold - scrollTop);
        // How much the threshold should be offset once it gets close to the
        // bottom of the page.
        const bottomAdd = Math.max(0, windowHeight - pixelsBelow - defaultDownThreshold);
        let adjustedBottomAdd = bottomAdd;

        // Adjusts bottomAdd for a small document. The calculation above
        // assumes the document is at least twice the windowheight in size. If
        // it is less than that, then bottomAdd needs to be shrunk
        // proportional to the difference in size.
        if (documentHeight < windowHeight * 2) {
            const maxPixelsBelow = documentHeight - windowHeight;
            const t = 1 - pixelsBelow / Math.max(1, maxPixelsBelow);
            const clamp = Math.max(0, Math.min(1, t));
            adjustedBottomAdd *= clamp;
        }

        let scrollingDown = true;
        if (scrollTop < lastKnownScrollPosition) {
            scrollingDown = false;
        }

        if (scrollingDown) {
            // When scrolling down, move the threshold up towards the default
            // downwards threshold position. If near the bottom of the page,
            // adjustedBottomAdd will offset the threshold towards the bottom
            // of the page.
            const amountScrolledDown = scrollTop - lastKnownScrollPosition;
            const adjustedDefault = defaultDownThreshold + adjustedBottomAdd;
            threshold = Math.max(adjustedDefault, threshold - amountScrolledDown);
        } else {
            // When scrolling up, move the threshold down towards the default
            // upwards threshold position. If near the bottom of the page,
            // quickly transition the threshold back up where it normally
            // belongs.
            const amountScrolledUp = lastKnownScrollPosition - scrollTop;
            const adjustedDefault = defaultUpThreshold - pixelsAbove
                + Math.max(0, adjustedBottomAdd - defaultDownThreshold);
            threshold = Math.min(adjustedDefault, threshold + amountScrolledUp);
        }

        if (documentHeight <= windowHeight) {
            threshold = 0;
        }

        if (thresholdDebug) {
            const id = 'mdbook-threshold-debug-data';
            let data = document.getElementById(id);
            if (data === null) {
                data = document.createElement('div');
                data.id = id;
                data.style.cssText = `
                    position: fixed;
                    top: 50px;
                    right: 10px;
                    background-color: 0xeeeeee;
                    z-index: 9999;
                    pointer-events: none;
                `;
                document.body.appendChild(data);
            }
            data.innerHTML = `
                <table>
                  <tr><td>documentHeight</td><td>${documentHeight.toFixed(1)}</td></tr>
                  <tr><td>windowHeight</td><td>${windowHeight.toFixed(1)}</td></tr>
                  <tr><td>scrollTop</td><td>${scrollTop.toFixed(1)}</td></tr>
                  <tr><td>pixelsAbove</td><td>${pixelsAbove.toFixed(1)}</td></tr>
                  <tr><td>pixelsBelow</td><td>${pixelsBelow.toFixed(1)}</td></tr>
                  <tr><td>bottomAdd</td><td>${bottomAdd.toFixed(1)}</td></tr>
                  <tr><td>adjustedBottomAdd</td><td>${adjustedBottomAdd.toFixed(1)}</td></tr>
                  <tr><td>scrollingDown</td><td>${scrollingDown}</td></tr>
                  <tr><td>threshold</td><td>${threshold.toFixed(1)}</td></tr>
                </table>
            `;
            drawDebugLine();
        }

        lastKnownScrollPosition = scrollTop;
    }

    function drawDebugLine() {
        if (!document.body) {
            return;
        }
        const id = 'mdbook-threshold-debug-line';
        const existingLine = document.getElementById(id);
        if (existingLine) {
            existingLine.remove();
        }
        const line = document.createElement('div');
        line.id = id;
        line.style.cssText = `
            position: fixed;
            top: ${threshold}px;
            left: 0;
            width: 100vw;
            height: 2px;
            background-color: red;
            z-index: 9999;
            pointer-events: none;
        `;
        document.body.appendChild(line);
    }

    function mdbookEnableThresholdDebug() {
        thresholdDebug = true;
        updateThreshold();
        drawDebugLine();
    }

    window.mdbookEnableThresholdDebug = mdbookEnableThresholdDebug;

    // Updates which headers in the sidebar should be expanded. If the current
    // header is inside a collapsed group, then it, and all its parents should
    // be expanded.
    function updateHeaderExpanded(currentA) {
        // Add expanded to all header-item li ancestors.
        let current = currentA.parentElement;
        while (current) {
            if (current.tagName === 'LI' && current.classList.contains('header-item')) {
                current.classList.add('expanded');
            }
            current = current.parentElement;
        }
    }

    // Updates which header is marked as the "current" header in the sidebar.
    // This is done with a virtual Y threshold, where headers at or below
    // that line will be considered the current one.
    function updateCurrentHeader() {
        if (!headers || !headers.length) {
            return;
        }

        // Reset the classes, which will be rebuilt below.
        const els = document.getElementsByClassName('current-header');
        for (const el of els) {
            el.classList.remove('current-header');
        }
        for (const toggle of headerToggles) {
            toggle.classList.remove('expanded');
        }

        // Find the last header that is above the threshold.
        let lastHeader = null;
        for (const header of headers) {
            const rect = header.getBoundingClientRect();
            if (rect.top <= threshold) {
                lastHeader = header;
            } else {
                break;
            }
        }
        if (lastHeader === null) {
            lastHeader = headers[0];
            const rect = lastHeader.getBoundingClientRect();
            const windowHeight = window.innerHeight;
            if (rect.top >= windowHeight) {
                return;
            }
        }

        // Get the anchor in the summary.
        const href = '#' + lastHeader.id;
        const a = [...document.querySelectorAll('.header-in-summary')]
            .find(element => element.getAttribute('href') === href);
        if (!a) {
            return;
        }

        a.classList.add('current-header');

        updateHeaderExpanded(a);
    }

    // Updates which header is "current" based on the threshold line.
    function reloadCurrentHeader() {
        if (disableScroll) {
            return;
        }
        updateThreshold();
        updateCurrentHeader();
    }


    // When clicking on a header in the sidebar, this adjusts the threshold so
    // that it is located next to the header. This is so that header becomes
    // "current".
    function headerThresholdClick(event) {
        // See disableScroll description why this is done.
        disableScroll = true;
        setTimeout(() => {
            disableScroll = false;
        }, 100);
        // requestAnimationFrame is used to delay the update of the "current"
        // header until after the scroll is done, and the header is in the new
        // position.
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                // Closest is needed because if it has child elements like <code>.
                const a = event.target.closest('a');
                const href = a.getAttribute('href');
                const targetId = href.substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    threshold = targetElement.getBoundingClientRect().bottom;
                    updateCurrentHeader();
                }
            });
        });
    }

    // Takes the nodes from the given head and copies them over to the
    // destination, along with some filtering.
    function filterHeader(source, dest) {
        const clone = source.cloneNode(true);
        clone.querySelectorAll('mark').forEach(mark => {
            mark.replaceWith(...mark.childNodes);
        });
        dest.append(...clone.childNodes);
    }

    // Scans page for headers and adds them to the sidebar.
    document.addEventListener('DOMContentLoaded', function() {
        const activeSection = document.querySelector('#mdbook-sidebar .active');
        if (activeSection === null) {
            return;
        }

        const main = document.getElementsByTagName('main')[0];
        headers = Array.from(main.querySelectorAll('h2, h3, h4, h5, h6'))
            .filter(h => h.id !== '' && h.children.length && h.children[0].tagName === 'A');

        if (headers.length === 0) {
            return;
        }

        // Build a tree of headers in the sidebar.

        const stack = [];

        const firstLevel = parseInt(headers[0].tagName.charAt(1));
        for (let i = 1; i < firstLevel; i++) {
            const ol = document.createElement('ol');
            ol.classList.add('section');
            if (stack.length > 0) {
                stack[stack.length - 1].ol.appendChild(ol);
            }
            stack.push({level: i + 1, ol: ol});
        }

        // The level where it will start folding deeply nested headers.
        const foldLevel = 3;

        for (let i = 0; i < headers.length; i++) {
            const header = headers[i];
            const level = parseInt(header.tagName.charAt(1));

            const currentLevel = stack[stack.length - 1].level;
            if (level > currentLevel) {
                // Begin nesting to this level.
                for (let nextLevel = currentLevel + 1; nextLevel <= level; nextLevel++) {
                    const ol = document.createElement('ol');
                    ol.classList.add('section');
                    const last = stack[stack.length - 1];
                    const lastChild = last.ol.lastChild;
                    // Handle the case where jumping more than one nesting
                    // level, which doesn't have a list item to place this new
                    // list inside of.
                    if (lastChild) {
                        lastChild.appendChild(ol);
                    } else {
                        last.ol.appendChild(ol);
                    }
                    stack.push({level: nextLevel, ol: ol});
                }
            } else if (level < currentLevel) {
                while (stack.length > 1 && stack[stack.length - 1].level > level) {
                    stack.pop();
                }
            }

            const li = document.createElement('li');
            li.classList.add('header-item');
            li.classList.add('expanded');
            if (level < foldLevel) {
                li.classList.add('expanded');
            }
            const span = document.createElement('span');
            span.classList.add('chapter-link-wrapper');
            const a = document.createElement('a');
            span.appendChild(a);
            a.href = '#' + header.id;
            a.classList.add('header-in-summary');
            filterHeader(header.children[0], a);
            a.addEventListener('click', headerThresholdClick);
            const nextHeader = headers[i + 1];
            if (nextHeader !== undefined) {
                const nextLevel = parseInt(nextHeader.tagName.charAt(1));
                if (nextLevel > level && level >= foldLevel) {
                    const toggle = document.createElement('a');
                    toggle.classList.add('chapter-fold-toggle');
                    toggle.classList.add('header-toggle');
                    toggle.addEventListener('click', () => {
                        li.classList.toggle('expanded');
                    });
                    const toggleDiv = document.createElement('div');
                    toggleDiv.textContent = '❱';
                    toggle.appendChild(toggleDiv);
                    span.appendChild(toggle);
                    headerToggles.push(li);
                }
            }
            li.appendChild(span);

            const currentParent = stack[stack.length - 1];
            currentParent.ol.appendChild(li);
        }

        const onThisPage = document.createElement('div');
        onThisPage.classList.add('on-this-page');
        onThisPage.append(stack[0].ol);
        const activeItemSpan = activeSection.parentElement;
        activeItemSpan.after(onThisPage);
    });

    document.addEventListener('DOMContentLoaded', reloadCurrentHeader);
    document.addEventListener('scroll', reloadCurrentHeader, { passive: true });
})();

