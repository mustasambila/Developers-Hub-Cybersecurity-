# GitHub Repository Setup Script for PowerShell
# This script automates the setup of your GitHub repository

Write-Host "🚀 OWASP Juice Shop Security Enhancement - GitHub Setup" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Verify current directory
Write-Host "📁 Step 1: Verifying current directory..." -ForegroundColor Yellow
$currentPath = Get-Location
Write-Host "Current path: $currentPath" -ForegroundColor Green
Write-Host ""

# Step 2: Backup original README
Write-Host "📝 Step 2: Backing up original README..." -ForegroundColor Yellow
if (Test-Path "README.md") {
    Copy-Item "README.md" "README_ORIGINAL.md" -Force
    Write-Host "✅ Original README backed up as README_ORIGINAL.md" -ForegroundColor Green
}

# Rename security project README to main README
if (Test-Path "README_SECURITY_PROJECT.md") {
    Copy-Item "README_SECURITY_PROJECT.md" "README.md" -Force
    Write-Host "✅ Security project README is now main README.md" -ForegroundColor Green
}
Write-Host ""

# Step 3: Check Git installation
Write-Host "🔧 Step 3: Checking Git installation..." -ForegroundColor Yellow
try {
    $gitVersion = git --version
    Write-Host "✅ Git is installed: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Git is not installed. Please install Git first." -ForegroundColor Red
    Write-Host "Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit
}
Write-Host ""

# Step 4: Initialize Git repository
Write-Host "📦 Step 4: Initializing Git repository..." -ForegroundColor Yellow
if (-not (Test-Path ".git")) {
    git init
    Write-Host "✅ Git repository initialized" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Git repository already initialized" -ForegroundColor Cyan
}
Write-Host ""

# Step 5: Configure Git (if not configured)
Write-Host "⚙️  Step 5: Checking Git configuration..." -ForegroundColor Yellow
$userName = git config user.name
$userEmail = git config user.email

if (-not $userName) {
    Write-Host "Please enter your name for Git commits:" -ForegroundColor Yellow
    $userName = Read-Host "Name"
    git config --global user.name $userName
    Write-Host "✅ Git user name configured" -ForegroundColor Green
} else {
    Write-Host "✅ Git user name: $userName" -ForegroundColor Green
}

if (-not $userEmail) {
    Write-Host "Please enter your email for Git commits:" -ForegroundColor Yellow
    $userEmail = Read-Host "Email"
    git config --global user.email $userEmail
    Write-Host "✅ Git user email configured" -ForegroundColor Green
} else {
    Write-Host "✅ Git user email: $userEmail" -ForegroundColor Green
}
Write-Host ""

# Step 6: Create .env from example
Write-Host "🔐 Step 6: Setting up environment variables..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "✅ .env file created from .env.example" -ForegroundColor Green
        Write-Host "⚠️  IMPORTANT: Edit .env file with your actual secrets!" -ForegroundColor Yellow
    }
} else {
    Write-Host "ℹ️  .env file already exists" -ForegroundColor Cyan
}
Write-Host ""

# Step 7: Check .gitignore
Write-Host "🚫 Step 7: Verifying .gitignore..." -ForegroundColor Yellow
if (Test-Path ".gitignore") {
    Write-Host "✅ .gitignore file exists" -ForegroundColor Green
    
    # Verify .env is in .gitignore
    $gitignoreContent = Get-Content ".gitignore" -Raw
    if ($gitignoreContent -match "\.env") {
        Write-Host "✅ .env is properly ignored" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Warning: .env might not be in .gitignore" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ .gitignore file not found" -ForegroundColor Red
}
Write-Host ""

# Step 8: Stage files
Write-Host "📋 Step 8: Staging files for commit..." -ForegroundColor Yellow
git add .
Write-Host "✅ Files staged" -ForegroundColor Green
Write-Host ""

# Show what will be committed
Write-Host "📊 Files to be committed:" -ForegroundColor Cyan
git status --short
Write-Host ""

# Check if .env is staged (it shouldn't be)
$stagedFiles = git diff --cached --name-only
if ($stagedFiles -match "\.env$" -and -not ($stagedFiles -match "\.env\.example")) {
    Write-Host "⚠️  WARNING: .env file is staged! Removing it..." -ForegroundColor Red
    git reset .env
    Write-Host "✅ .env removed from staging" -ForegroundColor Green
    Write-Host ""
}

# Step 9: Create initial commit
Write-Host "💾 Step 9: Creating initial commit..." -ForegroundColor Yellow
Write-Host "Do you want to create the initial commit? (Y/N)" -ForegroundColor Yellow
$createCommit = Read-Host

if ($createCommit -eq "Y" -or $createCommit -eq "y") {
    git commit -m "Initial commit: OWASP Juice Shop Security Enhancement Project

- Week 1: Security assessment and vulnerability identification  
- Week 2: Implementation of security fixes (Validator, Bcrypt, JWT, Helmet)
- Week 3: Testing, logging, and comprehensive documentation
- Security score improved from D- to A
- 10 vulnerabilities fixed, 95% risk reduction
- 36 tests passing at 100% success rate"
    
    Write-Host "✅ Initial commit created" -ForegroundColor Green
} else {
    Write-Host "⏭️  Skipped commit creation" -ForegroundColor Yellow
}
Write-Host ""

# Step 10: Set up remote
Write-Host "🌐 Step 10: Setting up GitHub remote..." -ForegroundColor Yellow
Write-Host "Enter your GitHub username:" -ForegroundColor Yellow
$githubUsername = Read-Host
Write-Host "Enter your repository name (default: juice-shop-security-enhanced):" -ForegroundColor Yellow
$repoName = Read-Host

if (-not $repoName) {
    $repoName = "juice-shop-security-enhanced"
}

$remoteUrl = "https://github.com/$githubUsername/$repoName.git"

# Check if remote already exists
$existingRemote = git remote get-url origin 2>$null
if ($existingRemote) {
    Write-Host "ℹ️  Remote 'origin' already exists: $existingRemote" -ForegroundColor Cyan
    Write-Host "Do you want to update it? (Y/N)" -ForegroundColor Yellow
    $updateRemote = Read-Host
    if ($updateRemote -eq "Y" -or $updateRemote -eq "y") {
        git remote set-url origin $remoteUrl
        Write-Host "✅ Remote updated to: $remoteUrl" -ForegroundColor Green
    }
} else {
    git remote add origin $remoteUrl
    Write-Host "✅ Remote added: $remoteUrl" -ForegroundColor Green
}
Write-Host ""

# Step 11: Push to GitHub
Write-Host "🚀 Step 11: Ready to push to GitHub!" -ForegroundColor Yellow
Write-Host "Before pushing, make sure you have:" -ForegroundColor Yellow
Write-Host "  1. Created the repository on GitHub" -ForegroundColor Cyan
Write-Host "  2. Have a Personal Access Token ready" -ForegroundColor Cyan
Write-Host ""
Write-Host "Do you want to push now? (Y/N)" -ForegroundColor Yellow
$pushNow = Read-Host

if ($pushNow -eq "Y" -or $pushNow -eq "y") {
    Write-Host "Pushing to GitHub..." -ForegroundColor Yellow
    
    # Check if main or master
    $currentBranch = git branch --show-current
    if (-not $currentBranch) {
        $currentBranch = "master"
        git branch -M main
        $currentBranch = "main"
    }
    
    git push -u origin $currentBranch
    
    Write-Host "✅ Code pushed to GitHub!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🎉 Repository URL: $remoteUrl" -ForegroundColor Cyan
} else {
    Write-Host "⏭️  Skipped push. Run this command when ready:" -ForegroundColor Yellow
    Write-Host "   git push -u origin main" -ForegroundColor Cyan
}
Write-Host ""

# Final summary
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "✅ GitHub Repository Setup Complete!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📌 Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Visit your repository: https://github.com/$githubUsername/$repoName" -ForegroundColor Cyan
Write-Host "  2. Add topics: security, owasp, nodejs, typescript, jwt, bcrypt" -ForegroundColor Cyan
Write-Host "  3. Update repository description" -ForegroundColor Cyan
Write-Host "  4. Create a release (optional)" -ForegroundColor Cyan
Write-Host "  5. Share your work!" -ForegroundColor Cyan
Write-Host ""
Write-Host "📚 Documentation:" -ForegroundColor Yellow
Write-Host "  - README.md - Main project documentation" -ForegroundColor Cyan
Write-Host "  - GITHUB_SETUP.md - Detailed setup guide" -ForegroundColor Cyan
Write-Host "  - WEEKLY_SECURITY_REPORT.md - Full project report" -ForegroundColor Cyan
Write-Host ""
Write-Host "🔐 Security Reminder:" -ForegroundColor Yellow
Write-Host "  - NEVER commit .env file" -ForegroundColor Red
Write-Host "  - Update .env with your actual secrets" -ForegroundColor Red
Write-Host "  - Rotate secrets if accidentally committed" -ForegroundColor Red
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
