package badlist

// popularNPM is the top npm packages to check typosquatting against.
var popularNPM = []string{
	"lodash", "react", "react-dom", "express", "axios", "moment",
	"webpack", "babel-core", "@babel/core", "typescript", "eslint",
	"prettier", "jest", "mocha", "chalk", "commander", "yargs",
	"cross-env", "dotenv", "uuid", "underscore", "jquery", "d3",
	"socket.io", "cors", "body-parser", "nodemon", "webpack-cli",
	"rimraf", "mkdirp", "glob", "minimist", "semver", "debug",
	"request", "got", "node-fetch", "sharp", "multer", "passport",
	"jsonwebtoken", "bcrypt", "mongoose", "sequelize", "knex",
	"pg", "mysql2", "redis", "ioredis", "bull", "agenda",
	"next", "nuxt", "gatsby", "vite", "rollup", "parcel",
	"tailwindcss", "postcss", "autoprefixer", "sass", "less",
}

// popularPyPI is the top PyPI packages to check typosquatting against.
var popularPyPI = []string{
	"requests", "numpy", "pandas", "matplotlib", "scipy", "sklearn",
	"scikit-learn", "tensorflow", "torch", "flask", "django",
	"fastapi", "sqlalchemy", "celery", "redis", "boto3", "pillow",
	"pydantic", "aiohttp", "httpx", "pytest", "black", "flake8",
	"mypy", "pylint", "click", "rich", "typer", "paramiko",
	"cryptography", "pyopenssl", "certifi", "urllib3", "chardet",
	"colorama", "tqdm", "setuptools", "pip", "wheel", "twine",
	"poetry", "virtualenv", "six", "attrs", "dacite", "marshmallow",
	"opencv-python", "cv2", "nltk", "spacy", "transformers",
	"huggingface-hub", "openai", "anthropic", "langchain",
	"xgboost", "lightgbm", "catboost", "optuna", "wandb",
}

// editDistance computes the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 1; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + min3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
			}
		}
	}
	return dp[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// typosquatTarget returns the name of a popular package this name is likely
// typosquatting, and the edit distance. Returns ("", 99) if no match.
func typosquatTarget(name string, eco string) (target string, dist int) {
	var popular []string
	switch eco {
	case "npm":
		popular = popularNPM
	case "pypi":
		popular = popularPyPI
	default:
		return "", 99
	}
	best, bestDist := "", 99
	for _, p := range popular {
		if name == p {
			return "", 99 // exact match = not a typosquat
		}
		d := editDistance(name, p)
		if d < bestDist {
			bestDist = d
			best = p
		}
	}
	return best, bestDist
}
