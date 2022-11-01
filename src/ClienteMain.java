import java.util.Scanner;

public class ClienteMain {
    public static void main(String[] args) throws Exception {
        System.out.println("...Starting ClienteMain...");

        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter (1 for 4), (2 for 16) or (3 for 32) Clients:");

        String choice = scanner.nextLine();

        int numClients = 0;

        if (choice.equals("1"))
            numClients = 4;
        else if (choice.equals("2"))
            numClients = 16;
        else if (choice.equals("3"))
            numClients = 32;
        else {
            System.err.println("Invalid choice");
            System.exit(-1);
        }


        scanner.close();

        for (int i = 0; i < numClients; i++) {
            ClienteThread ct = new ClienteThread();
            ct.start();
        }

    }
}
