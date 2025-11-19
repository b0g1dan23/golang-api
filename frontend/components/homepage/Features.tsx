import Image from "next/image";
import card_image from "@/public/Cards icon.png";
import coin_image from "@/public/Coin icon.png";
import purse_image from "@/public/Purse icon.png";

const Features = () => {
  return (
    <section>
      <div className="text-center mb-10!">
        <span className="text-sm uppercase">Features</span>
        <h2 className="text-2xl">What our product offers</h2>
      </div>
      <div className="flex gap-20 max-md:flex-col">
        <div className="flex-1 flex items-center flex-col text-center ">
          <Image src={card_image} alt="Card image" />
          <div className="flex flex-col gap-4.5 items-center mt-12">
            <h4>Customizable card</h4>
            <p className="max-w-100 text-center">
              Custom your own card for your exact incomes and expenses needs.
            </p>
          </div>
        </div>
        <div className="flex-1 flex items-center flex-col text-center ">
          <Image src={coin_image} alt="Coin image" />
          <div className="flex flex-col gap-4.5 items-center mt-12">
            <h4>No payment fee</h4>
            <p className="max-w-100 text-center">
              Transfer your payment all over the world with no payment fee.
            </p>
          </div>
        </div>
        <div className="flex-1 flex items-center flex-col text-center ">
          <Image src={purse_image} alt="Purse image" />
          <div className="flex flex-col gap-4.5 items-center mt-12">
            <h4>All in one place</h4>
            <p className="max-w-100 text-center">
              The right place to keep your credit and debit cards, boarding
              passes & more.
            </p>
          </div>
        </div>
      </div>
    </section >
  );
};
export default Features;
