customElements.define('steel-header', class extends HTMLElement {


    get active() {
        return this.getAttribute('active');
    }

    set active(value) {
        this.setAttribute('active', value);
    }

    mapKeyVals = {
        0: ['nav-item active', 'nav-item', 'nav-item'],
        1: ['nav-item', 'nav-item active', 'nav-item'],
        2: ['nav-item', 'nav-item', 'nav-item active'],
    };

    constructor() {
        super();
        let activeLocal = this.mapKeyVals[this.active]
        this.innerHTML = "<nav class=\"navbar navbar-expand-lg navbar-light bg-light\">\n" +
            "    <a class=\"navbar-brand\" href=\"#\">\n" +
            "        <img src=\"assets/logo.png\" width=45 height=\"45\" alt=\"\">\n" +
            "    </a>\n" +
            "    <button class=\"navbar-toggler\" type=\"button\" data-toggle=\"collapse\" data-target=\"#navbarNav\"\n" +
            "            aria-controls=\"navbarNav\" aria-expanded=\"false\" aria-label=\"Toggle navigation\">\n" +
            "        <span class=\"navbar-toggler-icon\"></span>\n" +
            "    </button>\n" +
            "    <div class=\"collapse navbar-collapse\" id=\"navbarNav\">\n" +
            "        <ul class=\"navbar-nav\">\n" +
            "            <li class=\"" +
            activeLocal[0] +
            "             \">\n" +
            "                <a class=\"nav-link\" href=\"index.html\">Home <span class=\"sr-only\">(current)</span></a>\n" +
            "            </li>\n" +
            "            <li class=\"" +
            activeLocal[1] +
            "             \">\n" +
            "                <a class=\"nav-link\" href=\"getstarted.html\">Get Started</a>\n" +
            "            </li>\n" +
            "            <li class=\"" +
            activeLocal[2] +
            "            \">\n" +
            "                <a class=\"nav-link\" href=\"#\">Docs</a>\n" +
            "            </li>\n" +
            //"            <li class=\"nav-item\">\n" +
            //"                <a class=\"nav-link\" href=\"#\" aria-disabled='true' disabled>Migration</a>\n" +
            //"            </li>\n" +
            "        </ul>\n" +
            "    </div>\n" +
            "</nav>";
    }
});
customElements.define('steel-footer', class extends HTMLElement {
    constructor() {
        super();
        this.innerHTML = "<hr class=\"my-4\">\n" +
            "\n" +
            "    <div class=\"container-fluid text-sm-left text-muted\">\n" +
            "        <p>©2020 Aditya Kishore</p>\n" +
            "        <p>Licensed under the Mozilla Public License 2.0</p>\n" +
            "        <p>Steel Crypt is a high-level wrapper over PointyCastle.</p>\n" +
            "        <p>Docs built on Bootstrap and served by GitHub.</p>\n" +
            "    </div>";
    }
});

