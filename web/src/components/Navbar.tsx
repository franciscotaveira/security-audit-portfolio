import React from 'react';

interface NavbarProps {
    onNavigate: (section: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onNavigate }) => {
    return (
        <nav className="navbar">
            <div className="container navbar-content">
                <a href="#" className="navbar-brand" onClick={() => onNavigate('hero')}>
                    <span className="navbar-logo">🔐</span>
                    <span>Solar Orion</span>
                </a>

                <div className="navbar-links">
                    <a
                        href="#vulnerabilities"
                        className="navbar-link"
                        onClick={(e) => { e.preventDefault(); onNavigate('vulnerabilities'); }}
                    >
                        Vulnerabilities
                    </a>
                    <a
                        href="#analyzer"
                        className="navbar-link"
                        onClick={(e) => { e.preventDefault(); onNavigate('analyzer'); }}
                    >
                        Analyzer
                    </a>
                    <a
                        href="#stats"
                        className="navbar-link"
                        onClick={(e) => { e.preventDefault(); onNavigate('stats'); }}
                    >
                        Stats
                    </a>
                    <a
                        href="https://github.com/franciscotaveira"
                        className="navbar-link"
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        GitHub
                    </a>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
