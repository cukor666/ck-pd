export namespace gen {
	
	export class Options {
	    length: number;
	    lowercase: boolean;
	    uppercase: boolean;
	    digits: boolean;
	    symbols: boolean;
	    excludeAmbiguous: boolean;
	    noRepeating: boolean;
	    requireEachClass: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Options(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.length = source["length"];
	        this.lowercase = source["lowercase"];
	        this.uppercase = source["uppercase"];
	        this.digits = source["digits"];
	        this.symbols = source["symbols"];
	        this.excludeAmbiguous = source["excludeAmbiguous"];
	        this.noRepeating = source["noRepeating"];
	        this.requireEachClass = source["requireEachClass"];
	    }
	}

}

export namespace main {
	
	export class Settings {
	    autoLockMinutes: number;
	    clipboardClearSeconds: number;
	    lockOnBlur: boolean;
	    lockOnMinimize: boolean;
	    theme: string;
	    sortMode: string;
	    revealNeedsConfirm: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autoLockMinutes = source["autoLockMinutes"];
	        this.clipboardClearSeconds = source["clipboardClearSeconds"];
	        this.lockOnBlur = source["lockOnBlur"];
	        this.lockOnMinimize = source["lockOnMinimize"];
	        this.theme = source["theme"];
	        this.sortMode = source["sortMode"];
	        this.revealNeedsConfirm = source["revealNeedsConfirm"];
	    }
	}
	export class AppInfo {
	    version: string;
	    vaultPath: string;
	    settingsPath: string;
	    portable: boolean;
	    platform: string;
	    settings: Settings;
	    entropyModel: string;
	    commonDictSize: number;
	
	    static createFrom(source: any = {}) {
	        return new AppInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.vaultPath = source["vaultPath"];
	        this.settingsPath = source["settingsPath"];
	        this.portable = source["portable"];
	        this.platform = source["platform"];
	        this.settings = this.convertValues(source["settings"], Settings);
	        this.entropyModel = source["entropyModel"];
	        this.commonDictSize = source["commonDictSize"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CopyFieldResult {
	    copied: boolean;
	    clearAfterSeconds: number;
	    field: string;
	    message: string;
	    generation: number;
	
	    static createFrom(source: any = {}) {
	        return new CopyFieldResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.copied = source["copied"];
	        this.clearAfterSeconds = source["clearAfterSeconds"];
	        this.field = source["field"];
	        this.message = source["message"];
	        this.generation = source["generation"];
	    }
	}
	export class RevealResult {
	    value: string;
	    generation: number;
	
	    static createFrom(source: any = {}) {
	        return new RevealResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.generation = source["generation"];
	    }
	}
	
	export class TOTPParsed {
	    secret: string;
	    algorithm: string;
	    digits: number;
	    period: number;
	    issuer: string;
	    account: string;
	
	    static createFrom(source: any = {}) {
	        return new TOTPParsed(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.secret = source["secret"];
	        this.algorithm = source["algorithm"];
	        this.digits = source["digits"];
	        this.period = source["period"];
	        this.issuer = source["issuer"];
	        this.account = source["account"];
	    }
	}
	export class TOTPResult {
	    code: string;
	    remaining: number;
	    period: number;
	    digits: number;
	    algorithm: string;
	    issuer: string;
	    account: string;
	
	    static createFrom(source: any = {}) {
	        return new TOTPResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.remaining = source["remaining"];
	        this.period = source["period"];
	        this.digits = source["digits"];
	        this.algorithm = source["algorithm"];
	        this.issuer = source["issuer"];
	        this.account = source["account"];
	    }
	}

}

export namespace strength {
	
	export class Result {
	    score: number;
	    label: string;
	    entropyBits: number;
	    guesses: string;
	    warnings: string[];
	    suggestions: string[];
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.score = source["score"];
	        this.label = source["label"];
	        this.entropyBits = source["entropyBits"];
	        this.guesses = source["guesses"];
	        this.warnings = source["warnings"];
	        this.suggestions = source["suggestions"];
	    }
	}

}

export namespace vault {
	
	export class BackupInfo {
	    path: string;
	    protected: boolean;
	    containerBytes: number;
	    vaultId: string;
	    createdAt: number;
	    sourcePath: string;
	
	    static createFrom(source: any = {}) {
	        return new BackupInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.protected = source["protected"];
	        this.containerBytes = source["containerBytes"];
	        this.vaultId = source["vaultId"];
	        this.createdAt = source["createdAt"];
	        this.sourcePath = source["sourcePath"];
	    }
	}
	export class BackupResult {
	    path: string;
	    bytes: number;
	    protected: boolean;
	    createdAt: number;
	    vaultId: string;
	    sourcePath: string;
	
	    static createFrom(source: any = {}) {
	        return new BackupResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.bytes = source["bytes"];
	        this.protected = source["protected"];
	        this.createdAt = source["createdAt"];
	        this.vaultId = source["vaultId"];
	        this.sourcePath = source["sourcePath"];
	    }
	}
	export class Detail {
	    id: string;
	    title: string;
	    username: string;
	    url: string;
	    tags: string[];
	    favorite: boolean;
	    hasTotp: boolean;
	    hasNotes: boolean;
	    created: number;
	    updated: number;
	    passwordLength: number;
	    passwordEmpty: boolean;
	    passwordWeak: boolean;
	    passwordReusedCount: number;
	    notes: string;
	    totpIssuer: string;
	    totpAccount: string;
	    totpAlgorithm: string;
	    totpDigits: number;
	    totpPeriod: number;
	
	    static createFrom(source: any = {}) {
	        return new Detail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.url = source["url"];
	        this.tags = source["tags"];
	        this.favorite = source["favorite"];
	        this.hasTotp = source["hasTotp"];
	        this.hasNotes = source["hasNotes"];
	        this.created = source["created"];
	        this.updated = source["updated"];
	        this.passwordLength = source["passwordLength"];
	        this.passwordEmpty = source["passwordEmpty"];
	        this.passwordWeak = source["passwordWeak"];
	        this.passwordReusedCount = source["passwordReusedCount"];
	        this.notes = source["notes"];
	        this.totpIssuer = source["totpIssuer"];
	        this.totpAccount = source["totpAccount"];
	        this.totpAlgorithm = source["totpAlgorithm"];
	        this.totpDigits = source["totpDigits"];
	        this.totpPeriod = source["totpPeriod"];
	    }
	}
	export class EntryInput {
	    id: string;
	    title: string;
	    username: string;
	    password: string;
	    keepPassword: boolean;
	    url: string;
	    notes: string;
	    tags: string[];
	    favorite: boolean;
	    totpSecret: string;
	    totpAlgorithm: string;
	    totpDigits: number;
	    totpPeriod: number;
	    totpIssuer: string;
	    totpAccount: string;
	    clearTotp: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EntryInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.keepPassword = source["keepPassword"];
	        this.url = source["url"];
	        this.notes = source["notes"];
	        this.tags = source["tags"];
	        this.favorite = source["favorite"];
	        this.totpSecret = source["totpSecret"];
	        this.totpAlgorithm = source["totpAlgorithm"];
	        this.totpDigits = source["totpDigits"];
	        this.totpPeriod = source["totpPeriod"];
	        this.totpIssuer = source["totpIssuer"];
	        this.totpAccount = source["totpAccount"];
	        this.clearTotp = source["clearTotp"];
	    }
	}
	export class Issue {
	    kind: string;
	    severity: string;
	    title: string;
	    detail: string;
	    entryId: string;
	    entryTitle: string;
	    score: number;
	    entropyBits: number;
	    reuseGroup: number;
	    entryUpdated: number;
	
	    static createFrom(source: any = {}) {
	        return new Issue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.severity = source["severity"];
	        this.title = source["title"];
	        this.detail = source["detail"];
	        this.entryId = source["entryId"];
	        this.entryTitle = source["entryTitle"];
	        this.score = source["score"];
	        this.entropyBits = source["entropyBits"];
	        this.reuseGroup = source["reuseGroup"];
	        this.entryUpdated = source["entryUpdated"];
	    }
	}
	export class Report {
	    total: number;
	    weak: number;
	    reused: number;
	    empty: number;
	    strong: number;
	    aging: number;
	    issues: Issue[];
	    checkedAt: number;
	    dictSize: number;
	    model: string;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.weak = source["weak"];
	        this.reused = source["reused"];
	        this.empty = source["empty"];
	        this.strong = source["strong"];
	        this.aging = source["aging"];
	        this.issues = this.convertValues(source["issues"], Issue);
	        this.checkedAt = source["checkedAt"];
	        this.dictSize = source["dictSize"];
	        this.model = source["model"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Status {
	    configured: boolean;
	    unlocked: boolean;
	    path: string;
	    vaultId: string;
	    entries: number;
	    revision: number;
	    updatedAt: number;
	    portable: boolean;
	    lastActive: number;
	    kdfMemoryKiB: number;
	    kdfIterations: number;
	    kdfParallelism: number;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.configured = source["configured"];
	        this.unlocked = source["unlocked"];
	        this.path = source["path"];
	        this.vaultId = source["vaultId"];
	        this.entries = source["entries"];
	        this.revision = source["revision"];
	        this.updatedAt = source["updatedAt"];
	        this.portable = source["portable"];
	        this.lastActive = source["lastActive"];
	        this.kdfMemoryKiB = source["kdfMemoryKiB"];
	        this.kdfIterations = source["kdfIterations"];
	        this.kdfParallelism = source["kdfParallelism"];
	    }
	}
	export class Summary {
	    id: string;
	    title: string;
	    username: string;
	    url: string;
	    tags: string[];
	    favorite: boolean;
	    hasTotp: boolean;
	    hasNotes: boolean;
	    created: number;
	    updated: number;
	    passwordLength: number;
	    passwordEmpty: boolean;
	    passwordWeak: boolean;
	    passwordReusedCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.username = source["username"];
	        this.url = source["url"];
	        this.tags = source["tags"];
	        this.favorite = source["favorite"];
	        this.hasTotp = source["hasTotp"];
	        this.hasNotes = source["hasNotes"];
	        this.created = source["created"];
	        this.updated = source["updated"];
	        this.passwordLength = source["passwordLength"];
	        this.passwordEmpty = source["passwordEmpty"];
	        this.passwordWeak = source["passwordWeak"];
	        this.passwordReusedCount = source["passwordReusedCount"];
	    }
	}

}

