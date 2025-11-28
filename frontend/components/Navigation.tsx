"use client";

import Link from "next/link";
import { Button } from "./ui/button";
import Logo from "./ui/Logo";
import { usePathname, useRouter } from "next/navigation";
import { IoIosMenu } from "react-icons/io";
import { useEffect, useState } from "react";
import { IoClose } from "react-icons/io5";
import { DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuTrigger } from "./ui/dropdown-menu";
import { toast } from "sonner";
import { BrowserClient } from "@/sdk/backend/browser-client";
import { User } from "@/models/user";

export interface NavigationItem {
  label: string;
  href: string;
  authenticated?: boolean;
}

export const navigationData: NavigationItem[] = [
  { label: "Home", href: "/" },
  { label: "Sign up", href: "/login?mode=signup", authenticated: false },
];

const Navigation = () => {
  const path = usePathname();
  const [showMenu, setShowMenu] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const router = useRouter();

  useEffect(() => {
    const fetchUser = async () => {
      const browserClient = new BrowserClient();
      const user = await browserClient.getUser();
      setUser(user);
      setIsLoaded(true);
    };
    fetchUser();
  }, []);

  return (
    <div
      className={`text-foreground bg-background border-b border-neutral-600 sticky top-0 z-50 shadow-nav transition-all duration-500 ease-in-out
                  ${isLoaded
          ? "translate-y-0 opacity-100"
          : "-translate-y-full opacity-0"
        }`}
    >
      <nav
        className={`flex py-6! items-center justify-between container relative z-20
                transition-all duration-300 ease-in-out`}
      >
        <Logo />

        {/* Desktop Menu */}
        <div className="flex items-center gap-14">
          <ul className="hidden lg:flex gap-10">
            {navigationData.filter(item => item.authenticated === undefined || item.authenticated === !!user).map((item) => (
              <li key={item.label}>
                <Link
                  href={item.href}
                  className={`uppercase ${path === item.href
                    ? "font-medium text-purple-400 transform-all duration-300 ease-in-out"
                    : "hover:font-medium transform-all duration-300 ease-in-out"
                    }
                `}
                >
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>

          <div className="flex items-center gap-4">
            {user && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <div className="max-lg:hidden h-10 w-10 rounded-full bg-purple-600 flex items-center justify-center cursor-pointer">
                    <span className="opacity-100! font-bold">{user.firstname.charAt(0)}</span>
                  </div>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="w-56" align="end">
                  <DropdownMenuLabel>My Account</DropdownMenuLabel>
                  <DropdownMenuGroup>
                    <DropdownMenuItem>
                      Profile
                      <DropdownMenuShortcut>⇧⌘P</DropdownMenuShortcut>
                    </DropdownMenuItem>
                    <DropdownMenuItem>
                      Billing
                      <DropdownMenuShortcut>⌘B</DropdownMenuShortcut>
                    </DropdownMenuItem>
                    <DropdownMenuItem>
                      Settings
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={async () => {
                    try {
                      const browserClient = new BrowserClient();
                      await browserClient.auth.signOut();
                      toast.success('Logged out successfully!');
                      router.push('/');
                      setUser(null);
                    } catch (err) {
                      const e = err as Error;
                      toast.error(e.message);
                    }
                  }}>
                    Log out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>

            )}
            {!user && (
              <Link href="/login" className="max-lg:hidden">
                <Button
                  size="lg"
                  className="hover:scale-105 active:scale-95"
                >
                  Login
                </Button>
              </Link>
            )}

            <button
              className="lg:hidden z-30 relative"
              onClick={() => setShowMenu((prev) => !prev)}
            >
              {showMenu ? <IoClose size={32} /> : <IoIosMenu size={32} />}
            </button>
          </div>
        </div>
      </nav>

      {/* Mobile Menu Dropdown */}
      <div
        className={`lg:hidden overflow-hidden transition-all duration-300 ease-in-out relative z-20
          ${showMenu ? "max-h-screen opacity-100" : "max-h-0 opacity-0"}`}
      >
        <ul className="flex flex-col gap-8 container py-8!">
          {navigationData.map((item) => (
            <li key={item.label}>
              <Link
                href={item.href}
                className={`${path === item.href
                  ? "font-extrabold text-purple-400 transform-all duration-300 ease-in-out"
                  : "hover:font-extrabold transform-all duration-300 ease-in-out"
                  }
                `}
                onClick={() => setShowMenu(false)}
              >
                {item.label}
              </Link>
            </li>
          ))}
          <li>
            <Link href="/login">
              <Button
                size="lg"
                variant="outline"
                className="w-full text-center hover:scale-105 active:scale-95"
                onClick={() => setShowMenu(false)}
              >
                Login
              </Button>
            </Link>
          </li>
        </ul>
      </div>

      {showMenu && (
        <div
          className="fixed inset-0 backdrop-blur-sm bg-neutral-900/20 z-10 lg:hidden"
          onClick={() => setShowMenu(false)}
        />
      )}
    </div>
  );
};
export default Navigation;
